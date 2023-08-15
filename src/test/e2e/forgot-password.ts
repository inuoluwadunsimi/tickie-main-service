//@ts-ignore
import request from 'supertest';
import app from '../../app';
import { connectDBForTesting } from '../connect.db.for.testing';
//@ts-ignore
import randomstring from 'randomstring';
import { JwtHelper } from '../../helpers/jwt.helper';
import { UserAuthDb } from '../../models';
import { JwtType } from '../../interfaces/user.verification';
import { staticUserAuthData, userData } from '../data/user';

export const forgotPasswordE2E = () => {
  randomstring.generate = jest.fn().mockReturnValue(userData.otp);
  JwtHelper.prototype.generateToken = jest.fn().mockReturnValueOnce(userData.forgotPasswordAuthToken);

  beforeAll(async () => {
    await connectDBForTesting();
  });

  it('should request OTP with email', function(done) {
    request(app)
      .post(' /user/auth/forgotpassword/otp-request')
      .set('x-device-id', userData.deviceId)
      .send({
        email: userData.email,
      })
      .expect(200, (err:any, res:any) => {
        if (err) return done(err);
        expect(res.body).toHaveProperty('message', 'OTP sent successfully');
        done();
      });
  });

  // test for non existing email
  it('should throw error if email does not exist', async function(done) {
    request(app)
      .post('/user/auth/forgotpassword/otp-request')
      .set('x-device-id', userData.deviceId)
      .send({
        email: staticUserAuthData.email,
      })
      .expect(400),
      async (err:any, res:any) => {
        if (err) return done(err);
        expect(res.body).toHaveProperty('message', 'user with this email does not exist');
        const authRecord = await UserAuthDb.findOne({ email: staticUserAuthData.email });
        expect(authRecord).toBe({});
      };
  });

  it('Should verify OTP', async done => {
    request(app)
      .post('user/auth/forgotpassword/otp-verify')
      .set('x-device-id', userData.deviceId)
      .send({
        email: userData.email,
        otp: userData.otp,
      })
      .expect(200, (err:any, res:any) => {
        if (err) return done(err);
        expect(res.body).toHaveProperty('token');
        expect(res.body.token).toBe(userData.forgotPasswordAuthToken);
        done();
      });
  });

  it('Should NOT verify OTP: Throw 400: Wrong OTP is sent', async done => {
    request(app)
      .post('user/auth/forgotpassword/otp-verify')
      .set('x-device-id', userData.deviceId)
      .send({
        email: userData.email,
        otp: '012345',
      })
      .expect(400, (err:any, res:any) => {
        if (err) return done(err);
        expect(res.body).toHaveProperty('message', 'Invalid OTP');
        done();
      });
  });

  it('should rest password new password', async done => {
    JwtHelper.prototype.verifyToken = jest.fn().mockReturnValue({
      email: userData.email,
      deviceId: userData.deviceId,
      type: JwtType.NEW_USER,
    });
    JwtHelper.prototype.generateToken = jest.fn().mockReturnValue(userData.authToken);
    request(app)
      .post(' /user/auth/forgotpassword/password-reset')
      .set('x-device-id', userData.deviceId)
      .set('x-auth-token', userData.signUpAuthToken)
      .send({
        password: userData.password,
      })
      .expect(200, async (err:any, res:any) => {
        if (err) return done(err);
        expect(res.body).toHaveProperty('token', userData.authToken);
      });
  });
};
