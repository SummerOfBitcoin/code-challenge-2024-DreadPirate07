const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// structure definitions that will be used throughout the code
class BlockHeader {
  constructor(version, prev_block_hash, merkle_root, timestamp, bits, nonce) {
    this.version = version;
    this.prev_block_hash = prev_block_hash;
    this.merkle_root = merkle_root;
    this.timestamp = timestamp;
    this.bits = bits;
    this.nonce = nonce;
  }
}

class Input {
  constructor(
    txid,
    vout,
    prevout,
    scriptsig,
    scriptsig_asm,
    witness,
    is_coinbase,
    sequence
  ) {
    this.txid = txid;
    this.vout = vout;
    this.prevout = prevout;
    this.scriptsig = scriptsig;
    this.scriptsig_asm = scriptsig_asm;
    this.witness = witness;
    this.is_coinbase = is_coinbase;
    this.sequence = sequence;
  }
}

class Prevout {
  constructor(
    scriptpubkey,
    scriptpubkey_asm,
    scriptpubkey_type,
    value,
    scriptpubkey_address = null
  ) {
    this.scriptpubkey = scriptpubkey;
    this.scriptpubkey_asm = scriptpubkey_asm;
    this.scriptpubkey_type = scriptpubkey_type;
    this.value = value;
    this.scriptpubkey_address = scriptpubkey_address;
  }
}

class Transaction {
  constructor(version, locktime, vin, vout) {
    this.version = version;
    this.locktime = locktime;
    this.vin = vin;
    this.vout = vout;
  }
}

class TxInfo {
  constructor(txid, wtxid, fee, weight) {
    this.txid = txid;
    this.wtxid = wtxid;
    this.fee = fee;
    this.weight = weight;
  }
}

class MerkleNode {
  constructor(left, data, right) {
    this.left = left;
    this.data = data;
    this.right = right;
  }
}

// Initializations of Header Block and target
const Bh = new BlockHeader(
  7,
  "0000000000000000000000000000000000000000000000000000000000000000",
  "",
  Math.floor(Date.now() / 1000),
  0x1f00ffff,
  0
);

const target =
  "0000ffff00000000000000000000000000000000000000000000000000000000";

/**
 * Creates a 2-byte buffer and writes a 16-bit
 * integer to it in little-endian format.
 * @returns buffer containing the written
 * value, suitable for binary data operations.
 */
function iTo16b(n) {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(n);
  return buffer;
}

/**
 * Allocates a 4-byte buffer and writes a 32-bit
 * integer to it in little-endian format.
 * @returns buffer, which can be used wherever
 * binary representation of integers is needed.
 */
function iTo32b(n) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(n);
  return buffer;
}

/**
 *
 * Initializes an 8-byte buffer and writes a 64-bit
 * integer as a BigInt in little-endian format.
 * @returns buffer, useful for
 * handling large integers in binary data formats.
 *
 */
function ito64b(n) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(BigInt(n));
  return buffer;
}

/**
 *
 * Utilizes the SHA-256 hashing algorithm from the
 * Node.js crypto module to hash provided data.
 * @returns the hash as a buffer, commonly used for
 * data integrity checks and cryptographic processes.
 *
 */
function sha(data) {
  const hash = crypto.createHash("sha256");
  hash.update(data);
  return hash.digest();
}

/**
 * Read and return the content of a file
 * specified by filename.
 */
function json(filename) {
  try {
    const data = fs.readFileSync(filename, "utf8");
    return [data, null];
  } catch (e) {
    return ["", e];
  }
}

/**
 *
 * Serializes an integer into a variable-length integer format
 * used in data structures, the size of the integer is dynamically
 * adjusted based on the value.
 * @returns  buffer containing the serialized variable-length integer.
 *
 */
function serInt(n) {
  if (n < 0xfd) {
    return Buffer.from([n]);
  } else if (n <= 0xffff) {
    return Buffer.concat([Buffer.from([0xfd]), iTo16b(n)]);
  } else if (n <= 0xffffffff) {
    return Buffer.concat([Buffer.from([0xfe]), iTo32b(n)]);
  } else {
    return Buffer.concat([Buffer.from([0xff]), ito64b(n)]);
  }
}

/**
 *
 * checks if a transaction is a Segregated Witness (SegWit)
 * transaction by checking if any of the transaction inputs (vin)
 * have a non-empty witness field.
 * @returns Boolean value (true if any input has a witness, false otherwise).
 */
function chkSegwit(tx) {
  for (const vin of tx.vin) {
    if (vin.witness.length > 0) {
      return true;
    }
  }
  return false;
}

/**
 * Reverses the byte order of the given data.
 * used for formatting hash outputs and
 * endian conversions.
 */
function reversebyte(data) {
  return Buffer.from(data).reverse();
}

/**
 *
 * Calculates the base size of a serialized transaction by
 * first serializing it and then measuring its length in bytes.
 * @returns length of the serialized transaction data in bytes.
 */

function baseSize(tx) {
  const serialized = serTransactions(tx);
  return serialized.length;
}

/**
 * Compares two byte arrays `a` and `b`.
 * @returns -1 if `a` is less than `b`, 1 if `a` is greater,
 * and 0 if they are equal.
 */
function compArrays(a, b) {
  if (a.length !== b.length) {
    throw new Error("Not same length");
  }

  for (let i = 0; i < a.length; i++) {
    if (a[i] < b[i]) {
      return -1;
    } else if (a[i] > b[i]) {
      return 1;
    }
  }

  return 0;
}

/**
 * Serializes a transaction object `tx` into a byte buffer.
 * @returns serialized byte buffer representing the transaction.
 */
function serTransactions(tx) {
  let serialdat = Buffer.alloc(0);
  serialdat = Buffer.concat([serialdat, iTo32b(tx.version)]);
  serialdat = Buffer.concat([serialdat, serInt(tx.vin.length)]);
  for (const vin of tx.vin) {
    serialdat = Buffer.concat([
      serialdat,
      reversebyte(Buffer.from(vin.txid, "hex")),
    ]);
    serialdat = Buffer.concat([serialdat, iTo32b(vin.vout)]);
    let scriptsigBytes;
    try {
      scriptsigBytes = Buffer.from(vin.scriptsig, "hex");
    } catch (e) {
      console.log(e);
      console.log(tx);
    }
    const lenScript = scriptsigBytes.length;
    serialdat = Buffer.concat([serialdat, serInt(lenScript)]);
    serialdat = Buffer.concat([serialdat, scriptsigBytes]);
    serialdat = Buffer.concat([serialdat, iTo32b(vin.sequence)]);
  }

  serialdat = Buffer.concat([serialdat, serInt(tx.vout.length)]);
  for (const vout of tx.vout) {
    serialdat = Buffer.concat([serialdat, ito64b(vout.value)]);
    const pubkeyB = Buffer.from(vout.scriptpubkey, "hex");
    const pubkeyLen = pubkeyB.length;
    serialdat = Buffer.concat([serialdat, serInt(pubkeyLen)]);
    serialdat = Buffer.concat([serialdat, pubkeyB]);
  }

  serialdat = Buffer.concat([serialdat, iTo32b(tx.locktime)]);
  return serialdat;
}

/**
 *
 * serializes a transaction with consideration for Segregated Witness data.
 * includes a marker and flag bytes (0x00, 0x01) and appends the witness data
 * for each input after the standard transaction.
 * @returns buffer containing the serialized transaction data which integrates both
 * non-SegWit and SegWit components
 */
function segwitSerialize(tx) {
  let serial = Buffer.alloc(0);
  const isSegwit = chkSegwit(tx);
  serial = Buffer.concat([serial, iTo32b(tx.version)]);
  if (isSegwit) {
    serial = Buffer.concat([serial, Buffer.from([0x00, 0x01])]);
  }
  serial = Buffer.concat([serial, serInt(tx.vin.length)]);
  for (const vin of tx.vin) {
    serial = Buffer.concat([serial, reversebyte(Buffer.from(vin.txid, "hex"))]);
    serial = Buffer.concat([serial, iTo32b(vin.vout)]);
    const pubkeyB = Buffer.from(vin.scriptsig, "hex");
    const scripLen = pubkeyB.length;
    serial = Buffer.concat([serial, serInt(scripLen)]);
    serial = Buffer.concat([serial, pubkeyB]);
    serial = Buffer.concat([serial, iTo32b(vin.sequence)]);
  }

  serial = Buffer.concat([serial, serInt(tx.vout.length)]);
  for (const vout of tx.vout) {
    serial = Buffer.concat([serial, ito64b(vout.value)]);
    const pubkeyScript = Buffer.from(vout.scriptpubkey, "hex");
    const scriptpubkeyLen = pubkeyScript.length;
    serial = Buffer.concat([serial, serInt(scriptpubkeyLen)]);
    serial = Buffer.concat([serial, pubkeyScript]);
  }

  if (isSegwit) {
    for (const vin of tx.vin) {
      const wtCount = vin.witness.length;
      serial = Buffer.concat([serial, serInt(wtCount)]);
      for (const witness of vin.witness) {
        const wtBytes = Buffer.from(witness, "hex");
        const witLen = wtBytes.length;
        serial = Buffer.concat([serial, serInt(witLen)]);
        serial = Buffer.concat([serial, wtBytes]);
      }
    }
  }

  serial = Buffer.concat([serial, iTo32b(tx.locktime)]);
  return serial;
}

/**
 *
 * serializes the header of a blockchain block by combining its
 * components such as the version, previous block hash,
 * merkle root, timestamp, bits (difficulty target), and nonce
 * into a single binary sequence.
 * @returns buffer containing the serialized form of the block header.
 */
function blockHeaderSerialdata(bh) {
  let serial = Buffer.alloc(0);
  serial = Buffer.concat([serial, iTo32b(bh.version)]);
  serial = Buffer.concat([serial, Buffer.from(bh.prev_block_hash, "hex")]);
  serial = Buffer.concat([serial, Buffer.from(bh.merkle_root, "hex")]);
  serial = Buffer.concat([serial, iTo32b(bh.timestamp)]);
  serial = Buffer.concat([serial, iTo32b(bh.bits)]);
  serial = Buffer.concat([serial, iTo32b(bh.nonce)]);
  return serial;
}

/**
 * Constructs a new Merkle node based on the left node `lnode`,
 * right node `rnode`, and data.
 * @returns returns the newly constructed merkle node.
 */
function newMerknode(lnode, rnode, data) {
  const merkNode = new MerkleNode(null, null, null);
  if (lnode === null && rnode === null) {
    merkNode.data = reversebyte(data);
  } else {
    const prevHash = Buffer.concat([lnode.data, rnode.data]);
    merkNode.data = sha(sha(prevHash));
  }
  merkNode.left = lnode;
  merkNode.right = rnode;
  return merkNode;
}

/**
 * constructs a Merkle tree from a list of leaf nodes.
 * @returns single node left in the nodes array.
 */
function newMerkTree(leaves) {
  const nodes = [];

  for (const leaf of leaves) {
    const data = Buffer.from(leaf, "hex");
    const node = newMerknode(null, null, data);
    nodes.push(node);
  }

  while (nodes.length > 1) {
    const newLevel = [];
    for (let i = 0; i < nodes.length; i += 2) {
      if (nodes.length % 2 !== 0) {
        nodes.push(nodes[nodes.length - 1]);
      }
      const node = newMerknode(nodes[i], nodes[i + 1], null);
      newLevel.push(node);
    }
    nodes.length = 0;
    nodes.push(...newLevel);
  }

  return nodes[0];
}

/**
 * Generates a witness commitment by prioritizing transaction IDs,
 * constructing a Merkle tree,
 * @returns witness commitment as a hexadecimal string.
 */
function witnessMerk() {
  const [, , wTxIds] = prioritize();
  const paddedWTxIds = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    ...wTxIds,
  ];
  const merkRoot = newMerkTree(paddedWTxIds);

  const commitString =
    merkRoot.data.toString("hex") +
    "0000000000000000000000000000000000000000000000000000000000000000";
  const wittCommit = Buffer.from(commitString, "hex");
  const wittCommitHash = sha(sha(wittCommit));

  return wittCommitHash.toString("hex");
}

/**
 * proof of work on a block header `bh` by adjusting
 * the nonce until the hash meets the target.
 * @returns true if proof of work is successful,
 * false if nonce limit is reached without success.
 */
function proofOfWork(bh) {
  const tgtBytes = Buffer.from(target, "hex");
  while (true) {
    const serialized = blockHeaderSerialdata(bh);
    const hash = reversebyte(sha(sha(serialized)));

    if (compArrays(hash, tgtBytes) === -1) {
      return true;
    }
    if (bh.nonce < 0x0 || bh.nonce > 0xffffffff) {
      return false;
    }
    bh.nonce++;
  }
}

/**
 * This function reads transaction data from files in the 'mempool' directory,
 * constructs transaction objects,calculates fees and weights, and then sorts
 * and selects transactions to be included in a new block based on
 * the highest fee per weight ratio. It prioritizes transactions to optimize
 * block rewards.
 * @returns total block reward in satoshis, along with lists of transaction IDs an
 * witness transaction IDs that are permitted.
 */
function prioritize() {
  const permtxIds = [];
  const permittedWTxIds = [];
  const dir = "./mempool";
  const files = fs.readdirSync(dir);
  const txInfo = [];
  let cnt = 0;
  for (const file of files) {
    cnt++;
    if (cnt > 4200) {
      break;
    }
    const txData = json(path.join(dir, file));
    const txDataObj = JSON.parse(txData[0]);
    const tx = new Transaction(
      txDataObj.version,
      txDataObj.locktime,
      txDataObj.vin.map(
        (vinData) =>
          new Input(
            vinData.txid,
            vinData.vout,
            new Prevout(
              vinData.prevout.scriptpubkey,
              vinData.prevout.scriptpubkey_asm,
              vinData.prevout.scriptpubkey_type,
              vinData.prevout.value,
              vinData.prevout.scriptpubkey_address
            ),
            vinData.scriptsig,
            vinData.scriptsig_asm,
            vinData.witness || [],
            vinData.is_coinbase,
            vinData.sequence
          )
      ),
      txDataObj.vout.map(
        (voutData) =>
          new Prevout(
            voutData.scriptpubkey,
            voutData.scriptpubkey_asm,
            voutData.scriptpubkey_type,
            voutData.value,
            voutData.scriptpubkey_address
          )
      )
    );
    let fee = 0;
    for (const vin of tx.vin) {
      fee += vin.prevout.value;
    }
    for (const vout of tx.vout) {
      fee -= vout.value;
    }
    const serialized = serTransactions(tx);
    const segSeral = segwitSerialize(tx);
    const txID = reversebyte(sha(sha(serialized))).toString("hex");
    const wtxID = reversebyte(sha(sha(segSeral))).toString("hex");
    txInfo.push(
      new TxInfo(txID, wtxID, fee, witnessSize(tx) + baseSize(tx) * 4)
    );
  }

  if (txInfo.length > 0) {
    const maxfeeperWight = Math.max(...txInfo.map((tx) => tx.fee / tx.weight));
    txInfo.sort(
      (a, b) =>
        b.fee / b.weight / maxfeeperWight - a.fee / a.weight / maxfeeperWight
    );
  }
  const permittingtxs = [];
  let permWieght = 3999300;
  let reward = 12.5; // Set the initial block reward
  for (const tx of txInfo) {
    if (permWieght >= tx.weight) {
      permittingtxs.push(tx);
      permWieght -= tx.weight;
      permtxIds.push(tx.txid);
      permittedWTxIds.push(tx.wtxid);
      reward += tx.fee; // Add the transaction fee to the reward
    }
  }

  return [reward * 100000000, permtxIds, permittedWTxIds]; // Convert reward to satoshis
}

/** Calculates the witness size of a transaction `tx`.
 *  @returns returns 0, if the transaction does not use SegWit,
 */
function witnessSize(tx) {
  if (!chkSegwit(tx)) {
    return 0;
  }

  let serialized = Buffer.alloc(0);
  const isSegwit = chkSegwit(tx);
  if (isSegwit) {
    serialized = Buffer.concat([serialized, Buffer.from([0x00, 0x01])]);
  }
  if (isSegwit) {
    for (const vin of tx.vin) {
      const witnessCount = vin.witness.length;
      serialized = Buffer.concat([serialized, serInt(witnessCount)]);
      for (const witness of vin.witness) {
        const witnessBytes = Buffer.from(witness, "hex");
        const witnessLen = witnessBytes.length;
        serialized = Buffer.concat([serialized, serInt(witnessLen)]);
        serialized = Buffer.concat([serialized, witnessBytes]);
      }
    }
  }

  return serialized.length;
}

/**
 * creates a coinbase transaction with the specified `netReward`.
 * @returns constructed coinbase transaction.
 */
function conibaseCreate(netReward) {
  const witCommit = witnessMerk();
  const coinbaseTx = new Transaction(
    1,
    0,
    [
      new Input(
        "0000000000000000000000000000000000000000000000000000000000000000",
        0xffffffff,
        new Prevout(
          "0014df4bf9f3621073202be59ae590f55f42879a21a0",
          "0014df4bf9f3621073202be59ae590f55f42879a21a0",
          "p2pkh",
          netReward,
          "bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c" // Pass scriptpubkey_address here
        ),
        "03951a0604f15ccf5609013803062b9b5a0100072f425443432f20",
        "03951a0604f15ccf5609013803062b9b5a0100072f425443432f20",
        ["0000000000000000000000000000000000000000000000000000000000000000"],
        true,
        0xffffffff
      ),
    ],
    [
      new Prevout(
        "0014df4bf9f3621073202be59ae590f55f42879a21a0",
        "0014df4bf9f3621073202be59ae590f55f42879a21a0",
        "p2pkh",
        netReward,
        "bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c" // Pass scriptpubkey_address here
      ),
      new Prevout(
        "6a24" + "aa21a9ed" + witCommit,
        "OP_RETURN" + "OP_PUSHBYTES_36" + "aa21a9ed" + witCommit,
        "op_return",
        0,
        "bc1qma9lnumzzpejq2l9ntjepa2lg2re5gdqn3nf0c" // Pass scriptpubkey_address here
      ),
    ]
  );
  return coinbaseTx;
}

function miningFunction() {
  const [netReward, txIds, _] = prioritize();

  const cbTx = conibaseCreate(netReward);
  const serialCoinbtx = serTransactions(cbTx);

  const padTxIds = [
    reversebyte(sha(sha(serialCoinbtx))).toString("hex"),
    ...txIds,
  ];
  const mkr = newMerkTree(padTxIds);
  Bh.merkle_root = mkr.data.toString("hex");

  if (proofOfWork(Bh)) {
    const serializedBh = blockHeaderSerialdata(Bh);
    const segSerialized = segwitSerialize(cbTx);
    fs.writeFileSync(
      "output.txt",
      serializedBh.toString("hex") +
        "\n" +
        segSerialized.toString("hex") +
        "\n" +
        padTxIds.join("\n")
    );
  }
}

function main() {
  miningFunction();
}

main();

