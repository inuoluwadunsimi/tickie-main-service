import express from 'express';
import {JwtHelper} from '../helpers/jwt.helper';
import { UserTokenDb } from '../models';
import { redisClient } from '../helpers/redis.connector';
import { JwtType } from '../interfaces/user.verification';
import {config} from '../constants/settings';
import { handleCreateTicket, handleEditTicketDetails } from '../controlllers/ticket';


const router = express.Router()

const jwtHelper = new JwtHelper({
  privateKey: config.jwtPrivateKey,
  UserTokenDb,
  redisClient: redisClient

})


router.post('/create-ticket',jwtHelper.requirePermission(JwtType.USER), handleCreateTicket)
router.put('/edit-ticket/:ticketId',jwtHelper.requirePermission(JwtType.USER),handleEditTicketDetails)

export default router
