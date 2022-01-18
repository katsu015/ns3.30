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

#include "youngdsr-network-queue.h"
#include "ns3/test.h"
#include <map>
#include <algorithm>
#include <functional>
#include "ns3/log.h"
#include "ns3/ipv4-route.h"
#include "ns3/socket.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("YoungdsrNetworkQueue");

namespace youngdsr {

NS_OBJECT_ENSURE_REGISTERED (YoungdsrNetworkQueue);

TypeId
YoungdsrNetworkQueue::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrNetworkQueue")
    .SetParent<Object> ()
    .SetGroupName ("Youngdsr")
    .AddConstructor<YoungdsrNetworkQueue>  ()
  ;
  return tid;
}

YoungdsrNetworkQueue::YoungdsrNetworkQueue (uint32_t maxLen, Time maxDelay)
  : m_size (0),
    m_maxSize (maxLen),
    m_maxDelay (maxDelay)
{
  NS_LOG_FUNCTION (this);
}

YoungdsrNetworkQueue::YoungdsrNetworkQueue () : m_size (0)
{
  NS_LOG_FUNCTION (this);
}

YoungdsrNetworkQueue::~YoungdsrNetworkQueue ()
{
  NS_LOG_FUNCTION (this);
  Flush ();
}

void
YoungdsrNetworkQueue::SetMaxNetworkSize (uint32_t maxSize)
{
  m_maxSize = maxSize;
}

void
YoungdsrNetworkQueue::SetMaxNetworkDelay (Time delay)
{
  m_maxDelay = delay;
}

uint32_t
YoungdsrNetworkQueue::GetMaxNetworkSize (void) const
{
  return m_maxSize;
}

Time
YoungdsrNetworkQueue::GetMaxNetworkDelay (void) const
{
  return m_maxDelay;
}

bool
YoungdsrNetworkQueue::FindPacketWithNexthop (Ipv4Address nextHop, YoungdsrNetworkQueueEntry & entry)
{
  Cleanup ();
  for (std::vector<YoungdsrNetworkQueueEntry>::iterator i = m_youngdsrNetworkQueue.begin (); i != m_youngdsrNetworkQueue.end (); ++i)
    {
      if (i->GetNextHopAddress () == nextHop)
        {
          entry = *i;
          i = m_youngdsrNetworkQueue.erase (i);
          return true;
        }
    }
  return false;
}

bool
YoungdsrNetworkQueue::Find (Ipv4Address nextHop)
{
  Cleanup ();
  for (std::vector<YoungdsrNetworkQueueEntry>::iterator i = m_youngdsrNetworkQueue.begin (); i != m_youngdsrNetworkQueue.end (); ++i)
    {
      if (i->GetNextHopAddress () == nextHop)
        {
          return true;
        }
    }
  return false;
}

bool
YoungdsrNetworkQueue::Enqueue (YoungdsrNetworkQueueEntry & entry)
{
  NS_LOG_FUNCTION (this << m_size << m_maxSize);
  if (m_size >= m_maxSize)
    {
      return false;
    }
  Time now = Simulator::Now ();
  entry.SetInsertedTimeStamp (now);
  m_youngdsrNetworkQueue.push_back (entry);
  m_size++;
  NS_LOG_LOGIC ("The network queue size is " << m_size);
  return true;
}

bool
YoungdsrNetworkQueue::Dequeue (YoungdsrNetworkQueueEntry & entry)
{
  NS_LOG_FUNCTION (this);
  Cleanup ();
  std::vector<YoungdsrNetworkQueueEntry>::iterator i = m_youngdsrNetworkQueue.begin ();
  if (i == m_youngdsrNetworkQueue.end ())
    {
      // no elements in array
      NS_LOG_LOGIC ("No queued packet in the network queue");
      return false;
    }
  entry = *i;
  m_youngdsrNetworkQueue.erase (i);
  m_size--;
  return true;
}

void
YoungdsrNetworkQueue::Cleanup (void)
{
  NS_LOG_FUNCTION (this);
  if (m_youngdsrNetworkQueue.empty ())
    {
      return;
    }

  Time now = Simulator::Now ();
  uint32_t n = 0;
  for (std::vector<YoungdsrNetworkQueueEntry>::iterator i = m_youngdsrNetworkQueue.begin (); i != m_youngdsrNetworkQueue.end (); )
    {
      if (i->GetInsertedTimeStamp () + m_maxDelay > now)
        {
          i++;
        }
      else
        {
          NS_LOG_LOGIC ("Outdated packet");
          i = m_youngdsrNetworkQueue.erase (i);
          n++;
        }
    }
  m_size -= n;
}

uint32_t
YoungdsrNetworkQueue::GetSize ()
{
  NS_LOG_FUNCTION (this);
  return m_size;
}

void
YoungdsrNetworkQueue::Flush (void)
{
  NS_LOG_FUNCTION (this);
  m_youngdsrNetworkQueue.erase (m_youngdsrNetworkQueue.begin (), m_youngdsrNetworkQueue.end ());
  m_size = 0;
}

}  // namespace youngdsr
}  // namespace ns3
