const path = require('path');

const entry = path.join(__dirname, 'index.js');
// console.log('entry: %s', entry);

module.exports = {
  mode: 'development',
  entry: entry,
  devServer: {
    static: './dist',
    historyApiFallback: true,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy': 'same-origin',
    },
  },
};
