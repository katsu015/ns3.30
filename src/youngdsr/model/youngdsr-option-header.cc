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
#include "youngdsr-option-header.h"
#include "ns3/ipv4-address.h"
#include "ns3/address-utils.h"
#include "ns3/packet.h"
#include "ns3/enum.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("YoungdsrOptionHeader");

namespace youngdsr {

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionHeader);

TypeId YoungdsrOptionHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionHeader")
    .AddConstructor<YoungdsrOptionHeader> ()
    .SetParent<Header> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionHeader::YoungdsrOptionHeader ()
  : m_type (0),
    m_length (0)
{
}

YoungdsrOptionHeader::~YoungdsrOptionHeader ()
{
}

void YoungdsrOptionHeader::SetType (uint8_t type)
{
  m_type = type;
}

uint8_t YoungdsrOptionHeader::GetType () const
{
  return m_type;
}

void YoungdsrOptionHeader::SetLength (uint8_t length)
{
  m_length = length;
}

uint8_t YoungdsrOptionHeader::GetLength () const
{
  return m_length;
}

void YoungdsrOptionHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)m_type << " length = " << (uint32_t)m_length << " )";
}

uint32_t YoungdsrOptionHeader::GetSerializedSize () const
{
  return m_length + 2;
}

void YoungdsrOptionHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (m_type);
  i.WriteU8 (m_length);
  i.Write (m_data.Begin (), m_data.End ());
}

uint32_t YoungdsrOptionHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  m_type = i.ReadU8 ();
  m_length = i.ReadU8 ();

  m_data = Buffer ();
  m_data.AddAtEnd (m_length);
  Buffer::Iterator dataStart = i;
  i.Next (m_length);
  Buffer::Iterator dataEnd = i;
  m_data.Begin ().Write (dataStart, dataEnd);

  return GetSerializedSize ();
}

YoungdsrOptionHeader::Alignment YoungdsrOptionHeader::GetAlignment () const
{
  Alignment retVal = { 1, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionPad1Header);

TypeId YoungdsrOptionPad1Header::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionPad1Header")
    .AddConstructor<YoungdsrOptionPad1Header> ()
    .SetParent<YoungdsrOptionHeader> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionPad1Header::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionPad1Header::YoungdsrOptionPad1Header ()
{
  SetType (224);
}

YoungdsrOptionPad1Header::~YoungdsrOptionPad1Header ()
{
}

void YoungdsrOptionPad1Header::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " )";
}

uint32_t YoungdsrOptionPad1Header::GetSerializedSize () const
{
  return 1;
}

void YoungdsrOptionPad1Header::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
}

uint32_t YoungdsrOptionPad1Header::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());

  return GetSerializedSize ();
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionPadnHeader);

TypeId YoungdsrOptionPadnHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionPadnHeader")
    .AddConstructor<YoungdsrOptionPadnHeader> ()
    .SetParent<YoungdsrOptionHeader> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionPadnHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionPadnHeader::YoungdsrOptionPadnHeader (uint32_t pad)
{
  SetType (0);
  NS_ASSERT_MSG (pad >= 2, "PadN must be at least 2 bytes long");
  SetLength (pad - 2);
}

YoungdsrOptionPadnHeader::~YoungdsrOptionPadnHeader ()
{
}

void YoungdsrOptionPadnHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength () << " )";
}

uint32_t YoungdsrOptionPadnHeader::GetSerializedSize () const
{
  return GetLength () + 2;
}

void YoungdsrOptionPadnHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());

  for (int padding = 0; padding < GetLength (); padding++)
    {
      i.WriteU8 (0);
    }
}

uint32_t YoungdsrOptionPadnHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());

  return GetSerializedSize ();
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionRreqHeader);

TypeId YoungdsrOptionRreqHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionRreqHeader")
    .AddConstructor<YoungdsrOptionRreqHeader> ()
    .SetParent<YoungdsrOptionHeader> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionRreqHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionRreqHeader::YoungdsrOptionRreqHeader ()
  : m_ipv4Address (0)
{
  SetType (1);
  SetLength (6 + m_ipv4Address.size () * 4);
}

YoungdsrOptionRreqHeader::~YoungdsrOptionRreqHeader ()
{
}

void YoungdsrOptionRreqHeader::SetNumberAddress (uint8_t n)
{
  m_ipv4Address.clear ();
  m_ipv4Address.assign (n, Ipv4Address ());
}

Ipv4Address YoungdsrOptionRreqHeader::GetTarget ()
{
  return m_target;
}

void YoungdsrOptionRreqHeader::SetTarget (Ipv4Address target)
{
  m_target = target;
}

void YoungdsrOptionRreqHeader::AddNodeAddress (Ipv4Address ipv4)
{
  m_ipv4Address.push_back (ipv4);
  SetLength (6 + m_ipv4Address.size () * 4);
}

void YoungdsrOptionRreqHeader::SetNodesAddress (std::vector<Ipv4Address> ipv4Address)
{
  m_ipv4Address = ipv4Address;
  SetLength (6 + m_ipv4Address.size () * 4);
}

std::vector<Ipv4Address> YoungdsrOptionRreqHeader::GetNodesAddresses () const
{
  return m_ipv4Address;
}

uint32_t YoungdsrOptionRreqHeader::GetNodesNumber () const
{
  return m_ipv4Address.size ();
}

void YoungdsrOptionRreqHeader::SetNodeAddress (uint8_t index, Ipv4Address addr)
{
  m_ipv4Address.at (index) = addr;
}

Ipv4Address YoungdsrOptionRreqHeader::GetNodeAddress (uint8_t index) const
{
  return m_ipv4Address.at (index);
}

void YoungdsrOptionRreqHeader::SetId (uint16_t identification)
{
  m_identification = identification;
}

uint16_t YoungdsrOptionRreqHeader::GetId () const
{
  return m_identification;
}

void YoungdsrOptionRreqHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength () << "";

  for (std::vector<Ipv4Address>::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      os << *it << " ";
    }

  os << ")";
}

uint32_t YoungdsrOptionRreqHeader::GetSerializedSize () const
{
  return 8 + m_ipv4Address.size () * 4;
}

void YoungdsrOptionRreqHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteHtonU16 (m_identification);
  WriteTo (i, m_target);

  for (VectorIpv4Address_t::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      it->Serialize (buff);
      i.Write (buff, 4);
    }
}

uint32_t YoungdsrOptionRreqHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  m_identification = i.ReadNtohU16 ();
  ReadFrom (i, m_target);

  uint8_t index = 0;
  for (std::vector<Ipv4Address>::iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      i.Read (buff, 4);
      m_address = it->Deserialize (buff);
      SetNodeAddress (index, m_address);
      ++index;
    }

  return GetSerializedSize ();
}

YoungdsrOptionHeader::Alignment YoungdsrOptionRreqHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionRrepHeader);

TypeId YoungdsrOptionRrepHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionRrepHeader")
    .AddConstructor<YoungdsrOptionRrepHeader> ()
    .SetParent<YoungdsrOptionHeader> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionRrepHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionRrepHeader::YoungdsrOptionRrepHeader ()
  : m_ipv4Address (0)
{
  SetType (2);
  SetLength (2 + m_ipv4Address.size () * 4);
}

YoungdsrOptionRrepHeader::~YoungdsrOptionRrepHeader ()
{
}

void YoungdsrOptionRrepHeader::SetNumberAddress (uint8_t n)
{
  m_ipv4Address.clear ();
  m_ipv4Address.assign (n, Ipv4Address ());
}

void YoungdsrOptionRrepHeader::SetNodesAddress (std::vector<Ipv4Address> ipv4Address)
{
  m_ipv4Address = ipv4Address;
  SetLength (2 + m_ipv4Address.size () * 4);
}

std::vector<Ipv4Address> YoungdsrOptionRrepHeader::GetNodesAddress () const
{
  return m_ipv4Address;
}

void YoungdsrOptionRrepHeader::SetNodeAddress (uint8_t index, Ipv4Address addr)
{
  m_ipv4Address.at (index) = addr;
}

Ipv4Address YoungdsrOptionRrepHeader::GetNodeAddress (uint8_t index) const
{
  return m_ipv4Address.at (index);
}

Ipv4Address YoungdsrOptionRrepHeader::GetTargetAddress (std::vector<Ipv4Address> ipv4Address) const
{
  return m_ipv4Address.at (ipv4Address.size () - 1);
}

void YoungdsrOptionRrepHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength () << "";

  for (std::vector<Ipv4Address>::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      os << *it << " ";
    }

  os << ")";
}

uint32_t YoungdsrOptionRrepHeader::GetSerializedSize () const
{
  return 4 + m_ipv4Address.size () * 4;
}

void YoungdsrOptionRrepHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU8 (0);
  i.WriteU8 (0);

  for (VectorIpv4Address_t::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      it->Serialize (buff);
      i.Write (buff, 4);
    }
}

uint32_t YoungdsrOptionRrepHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  i.ReadU8 ();
  i.ReadU8 ();

  uint8_t index = 0;
  for (std::vector<Ipv4Address>::iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      i.Read (buff, 4);
      m_address = it->Deserialize (buff);
      SetNodeAddress (index, m_address);
      ++index;
    }

  return GetSerializedSize ();
}

YoungdsrOptionHeader::Alignment YoungdsrOptionRrepHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionSRHeader);

TypeId YoungdsrOptionSRHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionSRHeader")
    .AddConstructor<YoungdsrOptionSRHeader> ()
    .SetParent<YoungdsrOptionHeader> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionSRHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionSRHeader::YoungdsrOptionSRHeader ()
  : m_segmentsLeft (0),
    m_ipv4Address (0)
{
  SetType (96);
  SetLength (2 + m_ipv4Address.size () * 4);
}

YoungdsrOptionSRHeader::~YoungdsrOptionSRHeader ()
{
}

void YoungdsrOptionSRHeader::SetSegmentsLeft (uint8_t segmentsLeft)
{
  m_segmentsLeft = segmentsLeft;
}

uint8_t YoungdsrOptionSRHeader::GetSegmentsLeft () const
{
  return m_segmentsLeft;
}

void YoungdsrOptionSRHeader::SetSalvage (uint8_t salvage)
{
  m_salvage = salvage;
}

uint8_t YoungdsrOptionSRHeader::GetSalvage () const
{
  return m_salvage;
}

void YoungdsrOptionSRHeader::SetNumberAddress (uint8_t n)
{
  m_ipv4Address.clear ();
  m_ipv4Address.assign (n, Ipv4Address ());
}

void YoungdsrOptionSRHeader::SetNodesAddress (std::vector<Ipv4Address> ipv4Address)
{
  m_ipv4Address = ipv4Address;
  SetLength (2 + m_ipv4Address.size () * 4);
}

std::vector<Ipv4Address> YoungdsrOptionSRHeader::GetNodesAddress () const
{
  return m_ipv4Address;
}

void YoungdsrOptionSRHeader::SetNodeAddress (uint8_t index, Ipv4Address addr)
{
  m_ipv4Address.at (index) = addr;
}

Ipv4Address YoungdsrOptionSRHeader::GetNodeAddress (uint8_t index) const
{
  return m_ipv4Address.at (index);
}

uint8_t YoungdsrOptionSRHeader::GetNodeListSize () const
{
  return m_ipv4Address.size ();
}

void YoungdsrOptionSRHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength () << "";

  for (std::vector<Ipv4Address>::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      os << *it << " ";
    }

  os << ")";
}

uint32_t YoungdsrOptionSRHeader::GetSerializedSize () const
{
  return 4 + m_ipv4Address.size () * 4;
}

void YoungdsrOptionSRHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU8 (m_salvage);
  i.WriteU8 (m_segmentsLeft);

  for (VectorIpv4Address_t::const_iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      it->Serialize (buff);
      i.Write (buff, 4);
    }
}

uint32_t YoungdsrOptionSRHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t buff[4];

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  m_salvage = i.ReadU8 ();
  m_segmentsLeft = i.ReadU8 ();

  uint8_t index = 0;
  for (std::vector<Ipv4Address>::iterator it = m_ipv4Address.begin (); it != m_ipv4Address.end (); it++)
    {
      i.Read (buff, 4);
      m_address = it->Deserialize (buff);
      SetNodeAddress (index, m_address);
      ++index;
    }

  return GetSerializedSize ();
}

YoungdsrOptionHeader::Alignment YoungdsrOptionSRHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionRerrHeader);

TypeId YoungdsrOptionRerrHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionRerrHeader")
    .AddConstructor<YoungdsrOptionRerrHeader> ()
    .SetParent<YoungdsrOptionHeader> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionRerrHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionRerrHeader::YoungdsrOptionRerrHeader ()
  : m_errorType (0),
    m_salvage (0),
    m_errorLength (4)
{
  SetType (3);
  SetLength (18);
}

YoungdsrOptionRerrHeader::~YoungdsrOptionRerrHeader ()
{
}

void YoungdsrOptionRerrHeader::SetErrorType (uint8_t errorType)
{
  m_errorType = errorType;
}

uint8_t YoungdsrOptionRerrHeader::GetErrorType () const
{
  return m_errorType;
}

void YoungdsrOptionRerrHeader::SetSalvage (uint8_t salvage)
{
  m_salvage = salvage;
}

uint8_t YoungdsrOptionRerrHeader::GetSalvage () const
{
  return m_salvage;
}

void YoungdsrOptionRerrHeader::SetErrorSrc (Ipv4Address errorSrcAddress)
{
  m_errorSrcAddress = errorSrcAddress;
}

Ipv4Address YoungdsrOptionRerrHeader::GetErrorSrc () const
{
  return m_errorSrcAddress;
}

void YoungdsrOptionRerrHeader::SetErrorDst (Ipv4Address errorDstAddress)
{
  m_errorDstAddress = errorDstAddress;
}

Ipv4Address YoungdsrOptionRerrHeader::GetErrorDst () const
{
  return m_errorDstAddress;
}

void YoungdsrOptionRerrHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength ()
     << " errorType = " << (uint32_t)m_errorType << " salvage = " << (uint32_t)m_salvage
     << " error source = " << m_errorSrcAddress << " error dst = " << m_errorDstAddress << " )";

}

uint32_t YoungdsrOptionRerrHeader::GetSerializedSize () const
{
  return 20;
}

void YoungdsrOptionRerrHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU8 (m_errorType);
  i.WriteU8 (m_salvage);
  WriteTo (i, m_errorSrcAddress);
  WriteTo (i, m_errorDstAddress);
  i.Write (m_errorData.Begin (), m_errorData.End ());
}

uint32_t YoungdsrOptionRerrHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  m_errorType = i.ReadU8 ();
  m_salvage = i.ReadU8 ();
  ReadFrom (i, m_errorSrcAddress);
  ReadFrom (i, m_errorDstAddress);

  m_errorData = Buffer ();
  m_errorData.AddAtEnd (m_errorLength);
  Buffer::Iterator dataStart = i;
  i.Next (m_errorLength);
  Buffer::Iterator dataEnd = i;
  m_errorData.Begin ().Write (dataStart, dataEnd);

  return GetSerializedSize ();
}

YoungdsrOptionHeader::Alignment YoungdsrOptionRerrHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionRerrUnreachHeader);

TypeId YoungdsrOptionRerrUnreachHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionRerrUnreachHeader")
    .AddConstructor<YoungdsrOptionRerrUnreachHeader> ()
    .SetParent<YoungdsrOptionRerrHeader> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionRerrUnreachHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionRerrUnreachHeader::YoungdsrOptionRerrUnreachHeader ()
  : m_salvage (0)
{
  SetType (3);
  SetLength (18);
  SetErrorType (1);
}

YoungdsrOptionRerrUnreachHeader::~YoungdsrOptionRerrUnreachHeader ()
{
}

void YoungdsrOptionRerrUnreachHeader::SetSalvage (uint8_t salvage)
{
  m_salvage = salvage;
}

uint8_t YoungdsrOptionRerrUnreachHeader::GetSalvage () const
{
  return m_salvage;
}

void YoungdsrOptionRerrUnreachHeader::SetErrorSrc (Ipv4Address errorSrcAddress)
{
  m_errorSrcAddress = errorSrcAddress;
}

Ipv4Address YoungdsrOptionRerrUnreachHeader::GetErrorSrc () const
{
  return m_errorSrcAddress;
}

void YoungdsrOptionRerrUnreachHeader::SetErrorDst (Ipv4Address errorDstAddress)
{
  m_errorDstAddress = errorDstAddress;
}

Ipv4Address YoungdsrOptionRerrUnreachHeader::GetErrorDst () const
{
  return m_errorDstAddress;
}

void YoungdsrOptionRerrUnreachHeader::SetUnreachNode (Ipv4Address unreachNode)
{
  m_unreachNode = unreachNode;
}

Ipv4Address YoungdsrOptionRerrUnreachHeader::GetUnreachNode () const
{
  return m_unreachNode;
}

void YoungdsrOptionRerrUnreachHeader::SetOriginalDst (Ipv4Address originalDst)
{
  m_originalDst = originalDst;
}

Ipv4Address YoungdsrOptionRerrUnreachHeader::GetOriginalDst () const
{
  return m_originalDst;
}

void YoungdsrOptionRerrUnreachHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength ()
     << " errorType = " << (uint32_t)m_errorType << " salvage = " << (uint32_t)m_salvage
     << " error source = " << m_errorSrcAddress << " error dst = " << m_errorDstAddress
     << " unreach node = " <<  m_unreachNode << " )";
}

uint32_t YoungdsrOptionRerrUnreachHeader::GetSerializedSize () const
{
  return 20;
}

void YoungdsrOptionRerrUnreachHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU8 (GetErrorType ());
  i.WriteU8 (m_salvage);
  WriteTo (i, m_errorSrcAddress);
  WriteTo (i, m_errorDstAddress);
  WriteTo (i, m_unreachNode);
  WriteTo (i, m_originalDst);
}

uint32_t YoungdsrOptionRerrUnreachHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  SetErrorType (i.ReadU8 ());
  m_salvage = i.ReadU8 ();
  ReadFrom (i, m_errorSrcAddress);
  ReadFrom (i, m_errorDstAddress);
  ReadFrom (i, m_unreachNode);
  ReadFrom (i, m_originalDst);

  return GetSerializedSize ();
}

YoungdsrOptionHeader::Alignment YoungdsrOptionRerrUnreachHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionRerrUnsupportHeader);

TypeId YoungdsrOptionRerrUnsupportHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionRerrUnsupportHeader")
    .AddConstructor<YoungdsrOptionRerrUnsupportHeader> ()
    .SetParent<YoungdsrOptionRerrHeader> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionRerrUnsupportHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionRerrUnsupportHeader::YoungdsrOptionRerrUnsupportHeader ()
  : m_salvage (0)
{
  SetType (3);
  SetLength (14);
  SetErrorType (3);
}

YoungdsrOptionRerrUnsupportHeader::~YoungdsrOptionRerrUnsupportHeader ()
{
}

void YoungdsrOptionRerrUnsupportHeader::SetSalvage (uint8_t salvage)
{
  m_salvage = salvage;
}

uint8_t YoungdsrOptionRerrUnsupportHeader::GetSalvage () const
{
  return m_salvage;
}

void YoungdsrOptionRerrUnsupportHeader::SetErrorSrc (Ipv4Address errorSrcAddress)
{
  m_errorSrcAddress = errorSrcAddress;
}

Ipv4Address YoungdsrOptionRerrUnsupportHeader::GetErrorSrc () const
{
  return m_errorSrcAddress;
}

void YoungdsrOptionRerrUnsupportHeader::SetErrorDst (Ipv4Address errorDstAddress)
{
  m_errorDstAddress = errorDstAddress;
}

Ipv4Address YoungdsrOptionRerrUnsupportHeader::GetErrorDst () const
{
  return m_errorDstAddress;
}

void YoungdsrOptionRerrUnsupportHeader::SetUnsupported (uint16_t unsupport)
{
  m_unsupport = unsupport;
}

uint16_t YoungdsrOptionRerrUnsupportHeader::GetUnsupported () const
{
  return m_unsupport;
}

void YoungdsrOptionRerrUnsupportHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength ()
     << " errorType = " << (uint32_t)m_errorType << " salvage = " << (uint32_t)m_salvage
     << " error source = " << m_errorSrcAddress << " error dst = " << m_errorDstAddress
     << " unsupported option = " <<  m_unsupport << " )";

}

uint32_t YoungdsrOptionRerrUnsupportHeader::GetSerializedSize () const
{
  return 16;
}

void YoungdsrOptionRerrUnsupportHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU8 (GetErrorType ());
  i.WriteU8 (m_salvage);
  WriteTo (i, m_errorSrcAddress);
  WriteTo (i, m_errorDstAddress);
  i.WriteU16 (m_unsupport);

}

uint32_t YoungdsrOptionRerrUnsupportHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  SetErrorType (i.ReadU8 ());
  m_salvage = i.ReadU8 ();
  ReadFrom (i, m_errorSrcAddress);
  ReadFrom (i, m_errorDstAddress);
  m_unsupport = i.ReadU16 ();

  return GetSerializedSize ();
}

YoungdsrOptionHeader::Alignment YoungdsrOptionRerrUnsupportHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionAckReqHeader);

TypeId YoungdsrOptionAckReqHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionAckReqHeader")
    .AddConstructor<YoungdsrOptionAckReqHeader> ()
    .SetParent<YoungdsrOptionHeader> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionAckReqHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionAckReqHeader::YoungdsrOptionAckReqHeader ()
  : m_identification (0)

{
  SetType (160);
  SetLength (2);
}

YoungdsrOptionAckReqHeader::~YoungdsrOptionAckReqHeader ()
{
}

void YoungdsrOptionAckReqHeader::SetAckId (uint16_t identification)
{
  m_identification = identification;
}

uint16_t YoungdsrOptionAckReqHeader::GetAckId () const
{
  return m_identification;
}

void YoungdsrOptionAckReqHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength ()
     << " id = " << m_identification << " )";
}

uint32_t YoungdsrOptionAckReqHeader::GetSerializedSize () const
{
  return 4;
}

void YoungdsrOptionAckReqHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU16 (m_identification);
}

uint32_t YoungdsrOptionAckReqHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  m_identification = i.ReadU16 ();

  return GetSerializedSize ();
}

YoungdsrOptionHeader::Alignment YoungdsrOptionAckReqHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}

NS_OBJECT_ENSURE_REGISTERED (YoungdsrOptionAckHeader);

TypeId YoungdsrOptionAckHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrOptionAckHeader")
    .AddConstructor<YoungdsrOptionAckHeader> ()
    .SetParent<YoungdsrOptionHeader> ()
    .SetGroupName ("Youngdsr")
  ;
  return tid;
}

TypeId YoungdsrOptionAckHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

YoungdsrOptionAckHeader::YoungdsrOptionAckHeader ()
  :    m_identification (0)
{
  SetType (32);
  SetLength (10);
}

YoungdsrOptionAckHeader::~YoungdsrOptionAckHeader ()
{
}

void YoungdsrOptionAckHeader::SetAckId (uint16_t identification)
{
  m_identification = identification;
}

uint16_t YoungdsrOptionAckHeader::GetAckId () const
{
  return m_identification;
}

void YoungdsrOptionAckHeader::SetRealSrc (Ipv4Address realSrcAddress)
{
  m_realSrcAddress = realSrcAddress;
}

Ipv4Address YoungdsrOptionAckHeader::GetRealSrc () const
{
  return m_realSrcAddress;
}

void YoungdsrOptionAckHeader::SetRealDst (Ipv4Address realDstAddress)
{
  m_realDstAddress = realDstAddress;
}

Ipv4Address YoungdsrOptionAckHeader::GetRealDst () const
{
  return m_realDstAddress;
}

void YoungdsrOptionAckHeader::Print (std::ostream &os) const
{
  os << "( type = " << (uint32_t)GetType () << " length = " << (uint32_t)GetLength ()
     << " id = " << m_identification << " real src = " << m_realSrcAddress
     << " real dst = " << m_realDstAddress << " )";

}

uint32_t YoungdsrOptionAckHeader::GetSerializedSize () const
{
  return 12;
}

void YoungdsrOptionAckHeader::Serialize (Buffer::Iterator start) const
{
  Buffer::Iterator i = start;

  i.WriteU8 (GetType ());
  i.WriteU8 (GetLength ());
  i.WriteU16 (m_identification);
  WriteTo (i, m_realSrcAddress);
  WriteTo (i, m_realDstAddress);
}

uint32_t YoungdsrOptionAckHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;

  SetType (i.ReadU8 ());
  SetLength (i.ReadU8 ());
  m_identification = i.ReadU16 ();
  ReadFrom (i, m_realSrcAddress);
  ReadFrom (i, m_realDstAddress);

  return GetSerializedSize ();
}

YoungdsrOptionHeader::Alignment YoungdsrOptionAckHeader::GetAlignment () const
{
  Alignment retVal = { 4, 0 };
  return retVal;
}
} /* namespace youngdsr */
} /* namespace ns3 */
