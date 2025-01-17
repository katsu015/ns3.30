/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 Yufei Cheng
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Yufei Cheng   <yfcheng@ittc.ku.edu>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  http://wiki.ittc.ku.edu/resilinets
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */

#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/header.h"
#include "youngdsr-fs-header.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("YoungdsrFsHeader");

namespace youngdsr {

NS_OBJECT_ENSURE_REGISTERED (YoungdsrFsHeader);

TypeId YoungdsrFsHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrFsHeader")
    .AddConstructor<YoungdsrFsHeader> ()
    .SetParent<Header> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrFsHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrFsHeader::YoungdsrFsHeader ()
  : m_nextHeader (0),
    m_messageType (0),
    m_payloadLen (0),
    m_sourceId (0),
    m_destId (0),
    m_data (0)
{
}

YoungdsrFsHeader::~YoungdsrFsHeader ()
{
}

void YoungdsrFsHeader::SetNextHeader (uint8_t protocol)
{
  m_nextHeader = protocol;
}

uint8_t YoungdsrFsHeader::GetNextHeader () const
{
  return m_nextHeader;
}

void YoungdsrFsHeader::SetMessageType (uint8_t messageType)
{
  m_messageType = messageType;
}

uint8_t YoungdsrFsHeader::GetMessageType () const
{
  return m_messageType;
}

void YoungdsrFsHeader::SetPayloadLength (uint16_t length)
{
  m_payloadLen = length;
}

uint16_t YoungdsrFsHeader::GetPayloadLength () const
{
  return m_payloadLen;
}

void YoungdsrFsHeader::SetSourceId (uint16_t sourceId)
{
  m_sourceId = sourceId;
}

uint16_t YoungdsrFsHeader::GetSourceId () const
{
  return m_sourceId;
}

void YoungdsrFsHeader::SetDestId (uint16_t destId)
{
  m_destId = destId;
}

uint16_t YoungdsrFsHeader::GetDestId () const
{
  return m_destId;
}

void YoungdsrFsHeader::Print (std::ostream &os) const
{
  os
  << "nextHeader: " << (uint32_t)GetNextHeader () << " messageType: " << (uint32_t)GetMessageType ()
  << " sourceId: " << (uint32_t)GetSourceId () << " destinationId: " << (uint32_t)GetDestId ()
  << " length: " << (uint32_t)GetPayloadLength ();
}

uint32_t YoungdsrFsHeader::GetSerializedSize () const
{
  return 8;
}

void YoungdsrFsHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (m_nextHeader);
  i.WriteU8 (m_messageType);
  i.WriteU16 (m_sourceId);
  i.WriteU16 (m_destId);
  i.WriteU16 (m_payloadLen);

  i.Write (m_data.PeekData (), m_data.GetSize ());
}

uint32_t YoungdsrFsHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  m_nextHeader = i.ReadU8 ();
  m_messageType = i.ReadU8 ();
  m_sourceId = i.ReadU16 ();
  m_destId = i.ReadU16 ();
  m_payloadLen = i.ReadU16 ();

  uint32_t dataLength = GetPayloadLength ();
  uint8_t data[dataLength];
  i.Read (data, dataLength);

  if (dataLength > m_data.GetSize ())
    {
      m_data.AddAtEnd (dataLength - m_data.GetSize ());
    }
  else
    {
      m_data.RemoveAtEnd (m_data.GetSize () - dataLength);
    }

  i = m_data.Begin ();
  i.Write (data, dataLength);

  return GetSerializedSize ();
}

YoungdsrOptionField::YoungdsrOptionField (uint32_t optionsOffset)
  : m_optionData (0),
    m_optionsOffset (optionsOffset)
{
}

YoungdsrOptionField::~YoungdsrOptionField ()
{
}

uint32_t YoungdsrOptionField::GetSerializedSize () const
{
  YoungdsrOptionHeader::Alignment align = {4,0};
  return m_optionData.GetSize () + CalculatePad (align);
}

void YoungdsrOptionField::Serialize (Buffer::Iterator start) const
{
  start.Write (m_optionData.Begin (), m_optionData.End ());
  YoungdsrOptionHeader::Alignment align = {4,0};
  uint32_t fill = CalculatePad (align);
  NS_LOG_LOGIC ("fill with " << fill << " bytes padding");
  switch (fill)
    {
    case 0:
      return;
    case 1:
      YoungdsrOptionPad1Header ().Serialize (start);
      return;
    default:
      YoungdsrOptionPadnHeader (fill).Serialize (start);
      return;
    }
}

uint32_t YoungdsrOptionField::Deserialize (Buffer::Iterator start, uint32_t length)
{
  uint8_t buf[length];
  start.Read (buf, length);
  m_optionData = Buffer ();
  m_optionData.AddAtEnd (length);
  m_optionData.Begin ().Write (buf, length);
  return length;
}

void YoungdsrOptionField::AddYoungdsrOption (YoungdsrOptionHeader const& option)
{
  NS_LOG_FUNCTION_NOARGS ();

  uint32_t pad = CalculatePad (option.GetAlignment ());
  NS_LOG_LOGIC ("need " << pad << " bytes padding");
  switch (pad)
    {
    case 0:
      break;       // no padding needed
    case 1:
      AddYoungdsrOption (YoungdsrOptionPad1Header ());
      break;
    default:
      AddYoungdsrOption (YoungdsrOptionPadnHeader (pad));
      break;
    }

  m_optionData.AddAtEnd (option.GetSerializedSize ());
  Buffer::Iterator it = m_optionData.End ();
  it.Prev (option.GetSerializedSize ());
  option.Serialize (it);
}

uint32_t YoungdsrOptionField::CalculatePad (YoungdsrOptionHeader::Alignment alignment) const
{
  return (alignment.offset - (m_optionData.GetSize () + m_optionsOffset)) % alignment.factor;
}

uint32_t YoungdsrOptionField::GetYoungdsrOptionsOffset ()
{
  return m_optionsOffset;
}

Buffer YoungdsrOptionField::GetYoungdsrOptionBuffer ()
{
  return m_optionData;
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrRoutingHeader);

TypeId YoungdsrRoutingHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::YoungdsrRoutingHeader")
    .AddConstructor<YoungdsrRoutingHeader> ()
    .SetParent<YoungdsrFsHeader> ()
  ;
  return tid;
}

TypeId YoungdsrRoutingHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrRoutingHeader::YoungdsrRoutingHeader ()
  : YoungdsrOptionField (8)
{
}

YoungdsrRoutingHeader::~YoungdsrRoutingHeader ()
{
}

void YoungdsrRoutingHeader::Print (std::ostream &os) const
{
  os
  << " nextHeader: " << (uint32_t)GetNextHeader () << " messageType: " << (uint32_t)GetMessageType ()
  << " sourceId: " << (uint32_t)GetSourceId () << " destinationId: " << (uint32_t)GetDestId ()
  << " length: " << (uint32_t)GetPayloadLength ();
}

uint32_t YoungdsrRoutingHeader::GetSerializedSize () const
{
  // 8 bytes is the YoungdsrFsHeader length
  return 8 + YoungdsrOptionField::GetSerializedSize ();
}

void YoungdsrRoutingHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetNextHeader ());
  i.WriteU8 (GetMessageType ());
  i.WriteU16 (GetSourceId ());
  i.WriteU16 (GetDestId ());
  i.WriteU16 (GetPayloadLength ());

  YoungdsrOptionField::Serialize (i);
}

uint32_t YoungdsrRoutingHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetNextHeader (i.ReadU8 ());
  SetMessageType (i.ReadU8 ());
  SetSourceId (i.ReadU16 ());
  SetDestId (i.ReadU16 ());
  SetPayloadLength (i.ReadU16 ());

  YoungdsrOptionField::Deserialize (i, GetPayloadLength ());

  return GetSerializedSize ();
}

}  /* namespace youngdsr */
}  /* namespace ns3 */
