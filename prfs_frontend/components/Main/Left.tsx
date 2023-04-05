import React from "react";
import axios from "axios";
import { ethers } from 'ethers';
import Web3 from 'web3';

import styles from "./Left.module.scss";

const TREE_DEPTH: number = 32;

const Left = (props: any) => {
  const [proof, setProof] = React.useState("");

  const handleClickGenProof = React.useCallback(async () => {
    const fetchData = async () => {
      console.log('fetch data');

      let accounts = await window.ethers.send('eth_requestAccounts', []);

      if (accounts != null && Array.isArray(accounts)) {
        const account = accounts[0];
        console.log('account', account);

        let u = ethers.utils;
        let signer = window.ethers.getSigner();

        const ethAddress = await signer.getAddress();
        console.log('ethAddress', ethAddress);

        const messageRaw = 'test';
        const messageHash = u.hashMessage(messageRaw);
        console.log('message hash', messageHash);

        const signature = await signer.signMessage(messageRaw);
        console.log('signature', signature, signature.length);

        const digest = u.arrayify(messageHash);

        const publicKey = u.recoverPublicKey(digest, signature);
        console.log('recovered publickey', publicKey);

        const computedAddress = u.computeAddress(publicKey);
        console.log('computed address', computedAddress);

        const recoveredAddress = u.recoverAddress(digest, signature)
        console.log('recovered address', recoveredAddress);

        let leafIdx = 0;
        let merklePath = getMerklePath(leafIdx, TREE_DEPTH);
        let setId = "1";

        try {
          let result = await axios.post("http://localhost:4000/get_nodes", {
            setId,
            merklePath,
          });

          // let { data } = await axios.post("http://localhost:4000/gen_proof", {
          //   address: account,
          //   publicKey,
          //   proofType: 'asset_proof_1',
          //   signature,
          //   path: [],
          //   leafIdx: 0,
          //   root: '',
          //   messageRaw,
          //   messageHash,
          // });

          let { data } = result;

          console.log('axios response', data);
          setProof(data.proof.join(", "));

        } catch (err) {
          console.log("Error fetching data, err: %s", err);
        }

      }
    };

    fetchData().then((_res) => { });
  }, [setProof]);

  return (
    <div className={styles.wrapper}>
      <div className={styles.leftLabel}></div>
      <button onClick={handleClickGenProof}>Generate proof</button>
      <div className={styles.desc}>
        Currently the only proof we support generating is <i>Asset proof</i>
      </div>
      <div>{proof}</div>
    </div>
  );
};

export default Left;

function getMerklePath(leafIdx: number, treeDepth: number): MerklePath[] {
  let currIdx = leafIdx;
  let merklePath: MerklePath[] = [];
  for (let h = 0; h < treeDepth - 1; h += 1) {
    let parentIdx = getParentIdx(currIdx);
    let parentSiblingIdx = getSiblingIdx(parentIdx);
    merklePath.push({
      posW: parentSiblingIdx,
      posH: h,
    });
    currIdx = parentIdx;
  }

  return merklePath;
}

function getSiblingIdx(idx: number): number {
  if (idx % 2 == 0) {
    return idx + 1;
  } else {
    return idx - 1;
  }
}

function getParentIdx(idx: number): number {
  return idx / 2;
}

export interface MerklePath {
  posW: number;
  posH: number;
}
