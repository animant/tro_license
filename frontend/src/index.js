import React, { Component, Fragment } from 'react';
import { render } from 'react-dom';

import TopBar from './TopBar';
import './style.css';
import * as KB from './keys-builder';

class App extends Component {
  constructor() {
    super();
    this.state = {
      name: 'React'
    };
  }

  handleClick() {
    let msgHash = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
    let signature = KB.generateKeyPair().sign(msgHash);
    console.error(
        KB.verifySignature(msgHash, signature)
    )
  }

  render() {
    return (
      <Fragment>
        <TopBar />
        <div className="container">
          <button className="generate-btn button" onClick={this.handleClick}>
            <i className="material-icons i-fingerprint">fingerprint</i>
            Click Me!
          </button>
        </div>
      </Fragment>
    );

  }
}

render(<App />, document.getElementById('root'));
