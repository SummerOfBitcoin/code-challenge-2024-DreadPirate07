# Summer of Bitcoin Assignment Solution Description

This project is aimed to simulate the process of mining. It involves selecting transactions, creating a new block, and validating the block. Below are the key concepts and steps used in the creation of this simulation process:

## Key Concepts:

- **Validating Transactions**: Making sure each transaction is correct, including the format and digital signatures.
- **Choosing Transactions**: Selecting transactions that offer the most fees for the space they use, to maximize earnings.
- **Creating a Merkle Tree**: Using to merkle tree method to organize transaction data that helps keep makes it easier to check transaction details.
- **Solving the Proof of Work**: Finding a special number (nonce) that proves the work done to secure the block.
- **Formatting the Block**: Arranging the block's data properly so that it can be read and recognized in the `output.txt` file

## Implementation Details

The implementation was broken down into several steps, each handled by specific functions within the script:

## Pseudo Code Outline

### Main Function

- Initialize the block header and set the target difficulty.
- Call the prioritize function to select and process transactions from the mempool.
- Create a coinbase transaction incorporating the selected transactions and calculated fees.
- Construct a Merkle tree using transaction IDs including the coinbase transactions.
- Perform the proof-of-work to find a valid nonce that satisfies the block's difficulty target.
- Serialize the block header and coinbase transaction.
- Write the serialized data and the transaction IDs to `output.txt`.

### Prioritize Transactions

- Read all transaction files from the mempool directory.
- For each transaction file:
  - Parse the JSON data into a Transaction object.
  - Validate and construct a transaction from parsed data.
  - Calculate the transaction fee and weight.
  - Store transaction details in a list.
- Sort the list of transactions based on the fee-to-weight ratio.
- Select transactions to include in the block, ensuring the total weight does not exceed the maximum block weight.
- Return details of the selected transactions with their cumulative fee.

### Construct Coinbase Transaction

- Calculate the total reward (=block reward + transaction fees).
- Create a coinbase transaction with inputs representing the block reward and outputs distributing the reward.

### Serialize Transaction

- Convert transaction details into a binary format for storage or transmission.
- Handle standard and SegWit transactions differently to include necessary components like witness data.

### Construct Merkle Tree

- For each transaction, compute the hash.
- Pair up transaction hashes and recursively compute hashes until a single Merkle root is obtained.

### Proof of Work

- Start with a nonce at 0.
- Serialize the block header with the current nonce.
- Compute the double SHA-256 hash of the serialized header.
- Check if the hash is below the target difficulty.
- Increment the nonce and repeat until a valid hash is found or the nonce space is exhausted.

### Output Construction

- Serialize the block header with the found nonce.
- Serialize the coinbase transaction.
- Write the serialized block header, coinbase transaction, and transaction IDs to `output.txt`.

### Utility Functions

- `toSha(data)`: Compute SHA-256 hash of data.
- `serializeTransaction(tx)` and `serializeBlockHeader(bh)` : Serialize transactions and block headers.
- `reverseBytes(data)`: Reverse the byte order of data for correct serialization formats.

## Results and Performance

The solution successfully mines a block containing transactions selected from a mempool based on their fee-per-weight ratio. The autograder results were as follows:

- **Score**: 98 (out of 100)
- **Total Fee**: 20194149
- **Maximum Fee**: 20616923
- **Total Weight**: 3999910
- **Maximum Weight**: 4000000

These results indicate that the solution not only meets the requirements but has also optimized the block space utilization and maximized the fee collection efficiently.

## Conclusion

This project provided valuable insights into the complexities of transaction selection, block construction, and the mining process in a bitcoin blockchain. Potential areas for future improvement in this project include:

- **Dynamic Transaction Validation**: Enhancing the validation logic to adapt to different types of blockchain transactions.
- **Optimization of Merkle Tree Construction**: Exploring more efficient algorithms to handle larger sets of transactions.
- **Scalability Testing**: Evaluating the script’s performance with significantly larger mempools and under different network conditions.

