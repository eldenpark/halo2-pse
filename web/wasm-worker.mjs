import { threads } from 'wasm-feature-detect';
import * as Comlink from 'comlink';

console.log('reading wasm-worker');

// Wrap wasm-bindgen exports (the `generate` function) to add time measurement.
function wrapExports({ generate }) {
  console.log(232);
  return ({ width, height, maxIterations }) => {
    console.log(11);
    const start = performance.now();
    const rawImageData = generate(width, height, maxIterations);
    const time = performance.now() - start;
    return {
      // Little perf boost to transfer data to the main thread w/o copying.
      rawImageData: Comlink.transfer(rawImageData, [rawImageData.buffer]),
      time
    };
  };
}

async function initHandlers() {
  console.log('init handlers()');

  let multiThread = (async () => {
    console.log('checking hardware concurrency');
    // If threads are unsupported in this browser, skip this handler.
    if (!(await threads())) {
      console.log('thread is not supported');
      return;
    }

    console.log("thread is supported");

    const multiThread = await import(
      './pkg-parallel/web.js'
    );

    await multiThread.default();
    await multiThread.initThreadPool(navigator.hardwareConcurrency);

    console.log(55)

    return wrapExports(multiThread);
  })();

  return Comlink.proxy({
    // singleThread,
    supportsThreads: !!multiThread,
    multiThread
  });
}

Comlink.expose({
  handlers: await initHandlers(),
});

