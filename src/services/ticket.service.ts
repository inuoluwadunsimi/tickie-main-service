import {TicketDb} from '../models/ticket';
import {EventDb} from '../models/event';
import {BadRequestError,NotFoundError} from '../interfaces';
import {
  TicketRequest,
  Ticket,
  UpdateTicketRequest,
  AllTicketsResponse,
  AllTicketsRequest
} from '../interfaces/ticket/ticket';

export async function createTicket(body:TicketRequest):Promise<Ticket>{

  const {user,name,event,description,price,type,total,available,isDraft} = body

  const linkedEvent = await EventDb.findById(event)
  if(!linkedEvent){
    throw new NotFoundError('This event does not exist')
  }
  if(linkedEvent?.creator !== user){
    throw new BadRequestError('unauthorised ticket creation')

  }

  const ticket = await  TicketDb.create({
    name,
    event,
    description,
    price,
    type,
    total,
    available,
    isDraft
  })
  return ticket as unknown as Ticket

}

export async function editTicketDetails(body:UpdateTicketRequest):Promise<Ticket>{
  const {user,name,event,description,price,type,total,available,ticket,isDraft} = body

  const linkedEvent = await EventDb.findById(event)
  if(!linkedEvent){
    throw new NotFoundError('This event does not exist')
  }
  if(linkedEvent?.creator !== user){
    throw new BadRequestError('unauthorised ticket creation')

  }

  await TicketDb.updateOne({id:ticket},{
    name,
    event,
    description,
    price,
    type,
    total,
    available,
    isDraft
  })

  const editedTicket = await TicketDb.findById(ticket)
  return editedTicket as unknown as Ticket

}

export async function getAllTickets(body:AllTicketsRequest):Promise<AllTicketsResponse>{

  const {event,page,limit,filter} = body
  const totalTickets = await TicketDb.find<Ticket>({event:event}).countDocuments()

  const totalPages = Math.ceil(totalTickets/limit)

  const allTickets = await TicketDb.find<Ticket>({event:event}).skip((page - 1) * limit).limit(limit)
  const filteredTicket = await TicketDb.find<Ticket>({event: event,type:filter})

 return{
    allTickets:allTickets,
    filteredTickets: filteredTicket,
    totalPages:totalPages,
 }

}
