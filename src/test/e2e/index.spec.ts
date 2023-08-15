import { forgotPasswordE2E } from './forgot-password';
import { signUpE2E } from './signup';
import { userE2E } from './user';

describe('SIGNUP FLOW', signUpE2E);
describe('USER FLOW', userE2E);
describe('FORGOT PASSWORD FLOW', forgotPasswordE2E);
