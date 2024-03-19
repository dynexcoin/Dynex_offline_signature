# Dynex Offline-Signature Client

The Dynex Offline-Signature Client is a tool which can be used to entirely move transaction signing offline. Your secret spend key never leaves your local environment and can sign transactions entirely disconnected from any public network. It is typically used by hardware wallet providers or for cold storage of larger DNX amounts.

# Build from source

To build from source, follow the following steps:

```
git clone https://github.com/dynexcoin/Dynex_offline_signature.git
``` 

Then navigate into the respective directory and perform:

``` 
mkdir build && cd build
cmake ..
make -j 8
``` 

This will build the binary 'offlinesignature'. You can run ```./offlinesignature -h``` for help.

# Usage

The following guide shows the manual steps for signing transactions offline. The steps can be automated. Please note that you are responsible for keeping secret keys confidential while working on the offline machine. 

## 1. Generate a new offline wallet address:

Generate a new (deterministic) DNX wallet address by running the following command on your offline signature machine:

``` 
./offlinesignature -generateaddress 
``` 

The keys are displayed in the terminal and also exported in the following two files:

- secretkeys.txt (make sure to keep this file strictly confidential)
- trackingkey.txt

```
passphrase      : unknown tavern aerial peeled hope ounce shuffled thwart aglow skater violin gesture topic wiggle echo patio kitchens pedantic thaw himself asleep wounded fuselage governing kitchens
Address         : XwmvQUv4QLTRDn1fmioSzM65k7uFtNcu63tcx47Z63oR9VKdxc6fhHgMFJUXEYUv4h9VaJ4No4sapMAx6ExafKBK2YwVXDxjk
spendPublicKey  : 20d5171ff98c90cdb70e9e604a421e61ca9148a8b0f11147359e122e989432bf
viewPublicKey   : 8b883816e547790bde0102b06d9232c636a8c93d046978990a2465f5dbfeb49c
spendSecretKey  : 4cec292ea6c4423d41c9732c29dc1764851a2643ed46252efbe894b0590f0909
viewSecretKey   : eff396a87a0ed17c4e6ad7ee8dac08bc2416752a5397f029ecdb95c0e1444a05
tracking key    : 20d5171ff98c90cdb70e9e604a421e61ca9148a8b0f11147359e122e989432bf8b883816e547790bde0102b06d9232c636a8c93d046978990a2465f5dbfeb49c0000000000000000000000000000000000000000000000000000000000000000eff396a87a0ed17c4e6ad7ee8dac08bc2416752a5397f029ecdb95c0e1444a05
````

### Notes: 
- The created wallet can safely receive DNX also when completely offline
- Users have the option to load the wallet with the passphrase also in regular CLI/GUI wallets
- The tracking key allows opening a "view only" wallet to track transactions and balances on an online machine

## 2. Open your generated wallet as "view only":

Start simplewallet with the tracking key of your offline wallet (view-only). Note that no outgoing transactions can be performed by this wallet in tracking mode. The secret spendkeys will remain entirely on the offline signing machine. To run a "view only" tracking wallet of your generated wallet, perform the following actions:

1. start simplewallet with the command ```./simplewallet```
2. choose option 'T' to import tracking wallet
3. choose & confirm password
4. paste the offline wallet's tracking key
5. syncronize

Note: this wallet does NOT contain the secret spend key. Transfers can only be signed with the offline-signature client.

## 3. Create & sign transactions offline:

To be able to sign and create transactions offline, the available outputs from your wallet have to be transferred from your tracking wallet to your offline signature machine:

### 3.1 Export outputs from your tracking wallet

Use the following command in your simplewallet:

```
export_to_offline keys.bin
```

This generates the file 'keys.bin' containing your spendable output keys.

Alternatively, available keys can also be queried from the walletd wallet service:

```
curl -d '{"jsonrpc":"2.0","id":1,"method":"exportOutputs","params":{"address":"<WALLET_ADDRESS"}}' http://localhost:8070/json_rpc
```

In this case, the returned json field 'message' contains the binary file data for 'keys.bin'

### 3.2 Create & sign a transaction on your offline signature machine


After you have transferred your 'keys.bin' file to your offline signature machine, you can create and sign a transaction with the following command:


``` 
./offlinesignature -signtransfer -address XwnYGHZjYCuGsHjAoHUsQ29VmmgnPqrCwhSqoihuVD7y2wBMfZ3WpdJCMdpvhBzyMa7idv16Dj8FTRXuc1EaH8dq2ziAW8brZ -amount 1.23 -keyfile keys.bin -outfile transfer.bin -secretvk 87aaf6c014f1829580e60f08e3bda7af5849785464fc62349912495782547003 -publicvk 34d8d6af7ffd43e4492a37b92bd12829dc619618e53292ac28cf4ef1be84e85c -secretsk e1063fa664bbe1d19e3aea82bba182fa11b9e6594f71ce946e3dcefcb0c9220c -publicsk 68d78e89c4de5edce3369b313d7732cb6f56eb840058f1cedfa979a201240b90
```

This command creates the file 'transfer.bin' containing your signed transaction.

### 3.3 Send your transaction

To send the transaction, transfer the file 'transfer.bin' to your tracking wallet and send it with the following command:

``` 
send_offline_tx transfer.bin
``` 

The transfer has been sent and will become available after 8 block confirmations. It is recommended to update the tracking wallet by using the command ```reset``` in the interface after a few block confirmations.

Alternatively can the created transaction (tx_as_hex) also be sent directly to the Dynex node using 

```
curl -X POST -i -H 'Accept: application/json' -d '{"params": {"tx_as_hex":"<TX_AS_HEX>"},"jsonrpc": "2.0", "id":"1"}' http://node.dynexcoin.org:18333/sendrawtransaction
``` 



