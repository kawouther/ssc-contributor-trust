// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/*
 * On-chain recording layer for the contributor trust framework.
 *
 * Trust scores are computed OFF-CHAIN (Eqs. 1-5); this layer only records them.
 * Four recording designs are provided so their cost can be compared:
 *
 *   A. TrustRegistryFull   - every CTS update is appended to contract storage.
 *   B. TrustRegistryEvent  - only the latest score is kept in storage; the full
 *                            history lives in event logs (cheaper, still
 *                            tamper-evident and verifiable from receipts).
 *   C. TrustAnchorBatch    - updates are logged off-chain; one Merkle root per
 *                            epoch is anchored on-chain; any single record can
 *                            later be verified against the anchored root. A
 *                            correction is a new leaf, in a later epoch, that
 *                            references the disputed record.
 *   D. TrustRegistryQuorum - design B, but a score is accepted only when k of n
 *                            independent evaluators submit it (removes the
 *                            single trusted off-chain evaluator).
 *
 * Privacy: contributors are identified only by a pseudonymous identifier
 *   pid = keccak256(platformAccountId || salt)   (salt kept off-chain),
 * and evidence only by its hash. No names, e-mails or raw evidence go on-chain.
 *
 * Scores are fixed-point int16 in [-1000, 1000]  (CTS * 1000).
 *
 * Immutability vs. correctability: records are never overwritten. An appeal
 * that succeeds is recorded as a new Correction record that supersedes the
 * disputed one, so the audit trail keeps both.
 */

abstract contract Roles {
    address public admin;                       // community governance (e.g. a multisig)
    mapping(address => bool) public isEvaluator; // off-chain trust-computation services

    error NotAdmin();
    error NotEvaluator();

    constructor() { admin = msg.sender; isEvaluator[msg.sender] = true; }

    modifier onlyAdmin()     { if (msg.sender != admin) revert NotAdmin(); _; }
    modifier onlyEvaluator() { if (!isEvaluator[msg.sender]) revert NotEvaluator(); _; }

    function setEvaluator(address who, bool allowed) external onlyAdmin { isEvaluator[who] = allowed; }

    /// Records which reviewers the platform assigned to a contribution, so that it is
    /// verifiable who was entitled to rate it (Eq. 8). Reviewers are identified by pid.
    event ReviewersAssigned(bytes32 indexed pid, bytes32 indexed contributionHash, bytes32[] reviewers);

    function assignReviewers(bytes32 pid, bytes32 contributionHash, bytes32[] calldata reviewers) external onlyEvaluator {
        emit ReviewersAssigned(pid, contributionHash, reviewers);
    }
}

/* --------------------------------------------------------------------------
 *  Design A - full history in storage
 * ------------------------------------------------------------------------ */
contract TrustRegistryFull is Roles {
    struct Record {            // packed into 2 storage slots
        int16   score;         // CTS * 1000
        uint8   kind;          // 0 init, 1 update, 2 correction
        uint40  timestamp;
        uint32  supersedes;    // index of corrected record (kind == 2)
        bytes32 evidenceHash;
    }

    mapping(bytes32 => Record[]) private history;

    event TrustRecorded(bytes32 indexed pid, uint256 indexed index, int16 score, uint8 kind, bytes32 evidenceHash);

    function register(bytes32 pid, int16 initialScore, bytes32 evidenceHash) external onlyAdmin {
        require(history[pid].length == 0, "exists");
        _push(pid, initialScore, 0, 0, evidenceHash);
    }

    function recordUpdate(bytes32 pid, int16 score, bytes32 evidenceHash) external onlyEvaluator {
        require(history[pid].length != 0, "unknown");
        _push(pid, score, 1, 0, evidenceHash);
    }

    function recordCorrection(bytes32 pid, uint32 disputedIndex, int16 corrected, bytes32 decisionHash) external onlyAdmin {
        require(disputedIndex < history[pid].length, "bad index");
        _push(pid, corrected, 2, disputedIndex, decisionHash);
    }

    function _push(bytes32 pid, int16 score, uint8 kind, uint32 supersedes, bytes32 ev) private {
        require(score >= -1000 && score <= 1000, "range");
        history[pid].push(Record(score, kind, uint40(block.timestamp), supersedes, ev));
        emit TrustRecorded(pid, history[pid].length - 1, score, kind, ev);
    }

    function latest(bytes32 pid) external view returns (int16) {
        Record[] storage h = history[pid];
        return h[h.length - 1].score;
    }

    function count(bytes32 pid) external view returns (uint256) { return history[pid].length; }
    function recordAt(bytes32 pid, uint256 i) external view returns (Record memory) { return history[pid][i]; }
}

/* --------------------------------------------------------------------------
 *  Design B - latest score in storage, history in event logs
 * ------------------------------------------------------------------------ */
contract TrustRegistryEvent is Roles {
    struct State {             // 1 storage slot
        int16  score;
        uint32 updates;
        uint40 lastUpdate;
        bool   exists;
    }

    mapping(bytes32 => State) public state;

    event TrustRecorded(bytes32 indexed pid, uint32 indexed seq, int16 score, uint8 kind, bytes32 evidenceHash);
    event TrustCorrected(bytes32 indexed pid, uint32 indexed disputedSeq, int16 corrected, bytes32 decisionHash);

    function register(bytes32 pid, int16 initialScore, bytes32 evidenceHash) external onlyAdmin {
        require(!state[pid].exists, "exists");
        require(initialScore >= -1000 && initialScore <= 1000, "range");
        state[pid] = State(initialScore, 0, uint40(block.timestamp), true);
        emit TrustRecorded(pid, 0, initialScore, 0, evidenceHash);
    }

    function recordUpdate(bytes32 pid, int16 score, bytes32 evidenceHash) external onlyEvaluator {
        State storage s = state[pid];
        require(s.exists, "unknown");
        require(score >= -1000 && score <= 1000, "range");
        unchecked { s.updates += 1; }
        s.score = score;
        s.lastUpdate = uint40(block.timestamp);
        emit TrustRecorded(pid, s.updates, score, 1, evidenceHash);
    }

    function recordCorrection(bytes32 pid, uint32 disputedSeq, int16 corrected, bytes32 decisionHash) external onlyAdmin {
        State storage s = state[pid];
        require(s.exists && disputedSeq <= s.updates, "bad seq");
        s.score = corrected;
        emit TrustCorrected(pid, disputedSeq, corrected, decisionHash);
    }
}

/* --------------------------------------------------------------------------
 *  Design C - Merkle-root anchoring per epoch
 * ------------------------------------------------------------------------ */
contract TrustAnchorBatch is Roles {
    struct Anchor { bytes32 root; uint32 count; uint40 timestamp; }

    mapping(uint64 => Anchor) public anchors;

    event EpochAnchored(uint64 indexed epoch, bytes32 root, uint32 count);

    function anchor(uint64 epoch, bytes32 root, uint32 count_) external onlyEvaluator {
        require(anchors[epoch].root == bytes32(0), "anchored");
        anchors[epoch] = Anchor(root, count_, uint40(block.timestamp));
        emit EpochAnchored(epoch, root, count_);
    }

    /// leaf = keccak256(abi.encode(pid, seq, score, evidenceHash)); sorted-pair Merkle tree
    function verify(uint64 epoch, bytes32 leaf, bytes32[] calldata proof) external view returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            h = h < p ? keccak256(abi.encodePacked(h, p)) : keccak256(abi.encodePacked(p, h));
        }
        return h == anchors[epoch].root;
    }
}

/* --------------------------------------------------------------------------
 *  Design D - k-of-n evaluator quorum (median of k submissions)
 * ------------------------------------------------------------------------ */
contract TrustRegistryQuorum is Roles {
    uint8 public immutable k;

    struct State { int16 score; uint32 round; bool exists; }
    struct Pending { bytes32 evidenceHash; uint8 n; int16[7] scores; }

    mapping(bytes32 => State) public state;
    mapping(bytes32 => Pending) private pending;               // pid => current round
    mapping(bytes32 => mapping(address => uint32)) private votedRound;

    event ScoreSubmitted(bytes32 indexed pid, uint32 indexed round, address evaluator, int16 score);
    event TrustRecorded(bytes32 indexed pid, uint32 indexed seq, int16 score, uint8 kind, bytes32 evidenceHash);
    event TrustCorrected(bytes32 indexed pid, uint32 indexed disputedSeq, int16 corrected, bytes32 decisionHash);

    constructor(uint8 k_) { require(k_ >= 1 && k_ <= 7, "k"); k = k_; }

    function register(bytes32 pid, int16 initialScore, bytes32 evidenceHash) external onlyAdmin {
        require(!state[pid].exists, "exists");
        state[pid] = State(initialScore, 1, true);
        emit TrustRecorded(pid, 0, initialScore, 0, evidenceHash);
    }

    function submit(bytes32 pid, int16 score, bytes32 evidenceHash) external onlyEvaluator {
        State storage s = state[pid];
        require(s.exists, "unknown");
        require(score >= -1000 && score <= 1000, "range");
        require(votedRound[pid][msg.sender] != s.round, "voted");
        votedRound[pid][msg.sender] = s.round;

        Pending storage p = pending[pid];
        if (p.n == 0) p.evidenceHash = evidenceHash;
        else require(p.evidenceHash == evidenceHash, "evidence mismatch");
        p.scores[p.n] = score;
        p.n += 1;
        emit ScoreSubmitted(pid, s.round, msg.sender, score);

        if (p.n == k) {
            int16 m = _median(p.scores, k);
            s.score = m;
            emit TrustRecorded(pid, s.round, m, 1, evidenceHash);
            s.round += 1;
            delete pending[pid];
        }
    }

    function recordCorrection(bytes32 pid, uint32 disputedSeq, int16 corrected, bytes32 decisionHash) external onlyAdmin {
        State storage s = state[pid];
        require(s.exists && disputedSeq < s.round, "bad seq");
        require(corrected >= -1000 && corrected <= 1000, "range");
        s.score = corrected;
        emit TrustCorrected(pid, disputedSeq, corrected, decisionHash);
    }

    function _median(int16[7] storage a, uint8 n) private view returns (int16) {
        int16[7] memory b = a;
        for (uint8 i = 1; i < n; i++) {          // insertion sort, n <= 7
            int16 x = b[i]; uint8 j = i;
            while (j > 0 && b[j - 1] > x) { b[j] = b[j - 1]; j--; }
            b[j] = x;
        }
        return b[n / 2];
    }
}
