import { describe } from 'mocha';
import Sinon from 'sinon';
import jwt from 'jsonwebtoken';
import * as ada from './index';
import { assert } from 'chai';

describe('Running Tests', function () {
  this.slow(0);
  let jwt_stub: any;
  let end_stub: any;
  const test_resp = {
    foo: 'bar',
  };
  before(() => {
    jwt_stub = Sinon.stub(jwt, 'verify')
      .callsFake(() => {
        return test_resp;
      });
    end_stub = Sinon.stub(ada, 'validateFromEndpoint')
      .resolves(test_resp);
  });
  after(() => {
    jwt_stub.restore();
    end_stub.restore();
  });
  it('should validate user local approach', async () => {
    const data = await ada.validate({
      fetchuser: false,
      token: 'Bearer xyz',
    });
    assert.equal(data, test_resp);
  });
  it('should validate user endpoint approach', async () => {
    const data = await ada.validate({
      fetchuser: true,
      token: 'Bearer xyz',
      app_id: 'test_app',
    });
    assert.equal(data, test_resp);
  });
});