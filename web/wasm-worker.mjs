import { threads } from 'wasm-feature-detect';
import * as Comlink from 'comlink';

console.log(22);

// Wrap wasm-bindgen exports (the `generate` function) to add time measurement.
function wrapExports({ generate }) {
  return ({ width, height, maxIterations }) => {
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
  console.log('init handlers');

  let [singleThread, multiThread] = await Promise.all([
    (async () => {
      console.log('single');
      const singleThread = await import('./pkg/web.js');
      await singleThread.default();
      return wrapExports(singleThread);
    })(),
    (async () => {
      console.log('checking hardware concurrency');
      // If threads are unsupported in this browser, skip this handler.
      if (!(await threads())) {
        console.log('thread is not supported');
        return;
      }

      const multiThread = await import(
        './pkg-parallel/web.js'
      );

      await multiThread.default();
      await multiThread.initThreadPool(navigator.hardwareConcurrency);

      return wrapExports(multiThread);
    })()
  ]);

  console.log('handlers are ready');

  return Comlink.proxy({
    singleThread,
    supportsThreads: !!multiThread,
    multiThread
  });
}

Comlink.expose({
  handlers: await initHandlers(),
});

