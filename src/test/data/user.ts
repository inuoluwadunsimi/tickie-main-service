import { faker } from '@faker-js/faker';

export const userData = {
  email: faker.internet.email(),
  deviceId: faker.string.uuid(),
  fullName: faker.internet.displayName(),
  password: 'Janetdoesnotloveyou234$',
  otp: faker.string.numeric(6),
  signUpAuthToken: faker.string.alphanumeric(32),
  forgotPasswordAuthToken: faker.string.alphanumeric(32),
  authToken: faker.string.alphanumeric(32),
};

export const staticUserAuthData = {
  email: 'fred@gmail.com',
  fullName: 'Alade Victor',
  password: 'Sapaistherealenemy12$',
  recognisedDevices:['1234'],
  user:'1234567890',
};
