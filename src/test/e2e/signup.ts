// @ts-ignore
import request from 'supertest';

import app from '../../app';
import { connectDBForTesting } from '../connect.db.for.testing';
// @ts-ignore
import randomstring from 'randomstring';
import { JwtHelper } from '../../helpers/jwt.helper';
import { UserAuthDb, UserVerificationDb } from '../../models';
import { JwtType } from '../../interfaces/user.verification';
import { userData } from '../data/user';


export const signUpE2E = () => {
  randomstring.generate = jest.fn().mockReturnValueOnce(userData.otp);
  JwtHelper.prototype.generateToken = jest.fn().mockReturnValueOnce(userData.signUpAuthToken);

  // mock redis client
  beforeAll(async () => {
    await connectDBForTesting();
  });
  //
  // afterAll(async () => {
  //   done();
  //   // await dropAndDisconnectDBForTesting();
  // });

  it('Should request OTP with email', function (done) {
    request(app)
      .post('/user/auth/otp-request')
      .set('x-device-id', userData.deviceId)
      .send({
        email: userData.email,
      })
      .expect(200, (err, res) => {
        if (err) return done(err);
        expect(res.body).toHaveProperty('message', 'OTP sent successfully');
        done();
      });
  });

  it('Should verify OTP', async (done) => {
    request(app)
      .post('/user/auth/otp-verify/signup')
      .set('x-device-id', userData.deviceId)
      .send({
        email: userData.email,
        otp: userData.otp,
      })
      .expect(200, (err, res) => {
        if (err) return done(err);
        expect(res.body).toHaveProperty('token');
        expect(res.body.token).toBe(userData.signUpAuthToken);
        done();
      });
  });

  it('Should NOT verify OTP: Throw 400: Wrong OTP is sent', async (done) => {
    request(app)
      .post('/user/auth/otp-verify/signup')
      .set('x-device-id', userData.deviceId)
      .send({
        email: userData.email,
        otp: '012345',
      })
      .expect(400, (err, res) => {
        if (err) return done(err);
        expect(res.body).toHaveProperty('message', 'Invalid OTP');
        done();
      });
  });

  // test for expired OTP
  it('Should NOT verify OTP: Throw 400: OTP is expired', async (done) => {
    UserVerificationDb.findOne = jest.fn().mockResolvedValueOnce({
      expiresAt: new Date(Date.now() - 10 * 60 * 1000), // 10 minutes backwards
      deleteOne: jest.fn(),
    });
    request(app)
      .post('/user/auth/otp-verify/signup')
      .set('x-device-id', userData.deviceId)
      .send({
        email: userData.email,
        otp: userData.otp,
      })
      .expect(400, (err, res) => {
        if (err) return done(err);
        expect(res.body).toHaveProperty('message', 'OTP has expired');
        done();
      });
  });

  // sign uer up with data
  it('Should sign user up', async (done) => {
    // MOCK JwtHelper.verifyToken
    JwtHelper.prototype.verifyToken = jest.fn().mockReturnValueOnce({
      email: userData.email,
      deviceId: userData.deviceId,
      type: JwtType.NEW_USER,
    });
    // MOCK JwtHelper.generateToken
    JwtHelper.prototype.generateToken = jest.fn().mockReturnValueOnce(userData.authToken);
    request(app)
      .post('/user/auth/signup')
      .set('x-device-id', userData.deviceId)
      .set('x-auth-token', userData.signUpAuthToken)
      .send({
        email: userData.email,
        fullName: userData.fullName,
        password: userData.password,
      })
      .expect(200, async (err, res) => {
        if (err) {
          // console.log(res);
          return done(err);
        }
        expect(res.body).toHaveProperty('token', userData.authToken);
        expect(res.body).toHaveProperty('user');
        expect(res.body.user).toHaveProperty('email', userData.email.toLowerCase());
        expect(res.body.user).toHaveProperty('fullName', userData.fullName);

        const userAuthRecord = await UserAuthDb.findOne({ email: userData.email.toLowerCase() });
        expect(userAuthRecord).toHaveProperty('email', userData.email.toLowerCase());
        done();
      });
  });
};
