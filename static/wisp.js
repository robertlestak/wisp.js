
(() => {
  const go = new Go();
  // change this to your own path if hosting locally
  let wispJsBaseURL = 'https://wisp.day/js/';
  WebAssembly.instantiateStreaming(fetch(wispJsBaseURL + "main.wasm"), go.importObject).then((result) => {
      go.run(result.instance);
      // start your app here if you are dependent on the wasm module,
      // otherwise you can call the global functions as usual
  });
})()