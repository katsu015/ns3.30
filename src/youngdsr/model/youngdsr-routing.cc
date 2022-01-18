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

#define NS_LOG_APPEND_CONTEXT                                   \
  if (GetObject<Node> ()) { std::clog << "[node " << GetObject<Node> ()->GetId () << "] "; }

#include <list>
#include <ctime>
#include <map>
#include <limits>
#include <algorithm>
#include <iostream>

#include "ns3/config.h"
#include "ns3/enum.h"
#include "ns3/string.h"
#include "ns3/ptr.h"
#include "ns3/log.h"
#include "ns3/assert.h"
#include "ns3/uinteger.h"
#include "ns3/net-device.h"
#include "ns3/packet.h"
#include "ns3/boolean.h"
#include "ns3/node-list.h"
#include "ns3/double.h"
#include "ns3/pointer.h"
#include "ns3/timer.h"
#include "ns3/object-vector.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-route.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/icmpv4-l4-protocol.h"
#include "ns3/adhoc-wifi-mac.h"
#include "ns3/wifi-net-device.h"
#include "ns3/inet-socket-address.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/llc-snap-header.h"
#include "ns3/arp-header.h"
#include "ns3/ipv6-interface.h"

#include "youngdsr-rreq-table.h"
#include "youngdsr-rcache.h"
#include "youngdsr-routing.h"
#include "youngdsr-fs-header.h"
#include "youngdsr-options.h"

u_int32_t mcorrect = 0;
u_int32_t correctc = 0;
u_int32_t m_malicious = 7;
u_int32_t m_malicious2 = 8;
u_int32_t m_malicious3 = 9;
u_int32_t mfailed = 0;
u_int32_t failedR = 0;
/*
#define fname "nnumber.txt"
std::ofstream outputfile2(fname);
*/

#define fname "route.txt"

std::ofstream outputfile2(fname);

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("YoungdsrRouting");

namespace youngdsr {

NS_OBJECT_ENSURE_REGISTERED (YoungdsrRouting);

/* see http://www.iana.org/assignments/protocol-numbers */
const uint8_t YoungdsrRouting::PROT_NUMBER = 48;
/*
 * The extension header is the fixed size youngdsr header, it is response for recognizing DSR option types
 * and demux to right options to process the packet.
 *
 * The header format with neighboring layers is as follows:
 *
 +-+-+-+-+-+-+-+-+-+-+-
 |  Application Header |
 +-+-+-+-+-+-+-+-+-+-+-+
 |   Transport Header  |
 +-+-+-+-+-+-+-+-+-+-+-+
 |   Fixed DSR Header  |
 +---------------------+
 |     DSR Options     |
 +-+-+-+-+-+-+-+-+-+-+-+
 |      IP Header      |
 +-+-+-+-+-+-+-+-+-+-+-+
 */

TypeId YoungdsrRouting::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::youngdsr::YoungdsrRouting")
    .SetParent<IpL4Protocol> ()
    .SetGroupName ("Youngdsr")
    .AddConstructor<YoungdsrRouting> ()
    .AddAttribute ("RouteCache",
                   "The route cache for saving routes from "
                   "route discovery process.",
                   PointerValue (0),
                   MakePointerAccessor (&YoungdsrRouting::SetRouteCache,
                                        &YoungdsrRouting::GetRouteCache),
                   MakePointerChecker<YoungdsrRouteCache> ())
    .AddAttribute ("RreqTable",
                   "The request table to manage route requests.",
                   PointerValue (0),
                   MakePointerAccessor (&YoungdsrRouting::SetRequestTable,
                                        &YoungdsrRouting::GetRequestTable),
                   MakePointerChecker<YoungdsrRreqTable> ())
    .AddAttribute ("PassiveBuffer",
                   "The passive buffer to manage "
                   "promisucously received passive ack.",
                   PointerValue (0),
                   MakePointerAccessor (&YoungdsrRouting::SetPassiveBuffer,
                                        &YoungdsrRouting::GetPassiveBuffer),
                   MakePointerChecker<YoungdsrPassiveBuffer> ())
    .AddAttribute ("MaxSendBuffLen",
                   "Maximum number of packets that can be stored "
                   "in send buffer.",
                   UintegerValue (64),
                   MakeUintegerAccessor (&YoungdsrRouting::m_maxSendBuffLen),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxSendBuffTime",
                   "Maximum time packets can be queued in the send buffer .",
                   TimeValue (Seconds (30)),
                   MakeTimeAccessor (&YoungdsrRouting::m_sendBufferTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("MaxMaintLen",
                   "Maximum number of packets that can be stored "
                   "in maintenance buffer.",
                   UintegerValue (50),
                   MakeUintegerAccessor (&YoungdsrRouting::m_maxMaintainLen),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxMaintTime",
                   "Maximum time packets can be queued in maintenance buffer.",
                   TimeValue (Seconds (30)),
                   MakeTimeAccessor (&YoungdsrRouting::m_maxMaintainTime),
                   MakeTimeChecker ())
    .AddAttribute ("MaxCacheLen",
                   "Maximum number of route entries that can be stored "
                   "in route cache.",
                   UintegerValue (64),
                   MakeUintegerAccessor (&YoungdsrRouting::m_maxCacheLen),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RouteCacheTimeout",
                   "Maximum time the route cache can be queued in "
                   "route cache.",
                   TimeValue (Seconds (300)),
                   MakeTimeAccessor (&YoungdsrRouting::m_maxCacheTime),
                   MakeTimeChecker ())
    .AddAttribute ("MaxEntriesEachDst",
                   "Maximum number of route entries for a "
                   "single destination to respond.",
                   UintegerValue (20),
                   MakeUintegerAccessor (&YoungdsrRouting::m_maxEntriesEachDst),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("SendBuffInterval",
                   "How often to check send buffer for packet with route.",
                   TimeValue (Seconds (500)),
                   MakeTimeAccessor (&YoungdsrRouting::m_sendBuffInterval),
                   MakeTimeChecker ())
    .AddAttribute ("NodeTraversalTime",
                   "The time it takes to traverse two neighboring nodes.",
                   TimeValue (MilliSeconds (40)),
                   MakeTimeAccessor (&YoungdsrRouting::m_nodeTraversalTime),
                   MakeTimeChecker ())
    .AddAttribute ("RreqRetries",
                   "Maximum number of retransmissions for "
                   "request discovery of a route.",
                   UintegerValue (16),
                   MakeUintegerAccessor (&YoungdsrRouting::m_rreqRetries),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaintenanceRetries",
                   "Maximum number of retransmissions for "
                   "data packets from maintenance buffer.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&YoungdsrRouting::m_maxMaintRexmt),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RequestTableSize",
                   "Maximum number of request entries in the request table, "
                   "set this as the number of nodes in the simulation.",
                   UintegerValue (64),
                   MakeUintegerAccessor (&YoungdsrRouting::m_requestTableSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RequestIdSize",
                   "Maximum number of request source Ids in "
                   "the request table.",
                   UintegerValue (16),
                   MakeUintegerAccessor (&YoungdsrRouting::m_requestTableIds),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("UniqueRequestIdSize",
                   "Maximum number of request Ids in "
                   "the request table for a single destination.",
                   UintegerValue (256),
                   MakeUintegerAccessor (&YoungdsrRouting::m_maxRreqId),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("NonPropRequestTimeout",
                   "The timeout value for non-propagation request.",
                   TimeValue (MilliSeconds (30)),
                   MakeTimeAccessor (&YoungdsrRouting::m_nonpropRequestTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("DiscoveryHopLimit",
                   "The max discovery hop limit for route requests.",
                   UintegerValue (255),
                   MakeUintegerAccessor (&YoungdsrRouting::m_discoveryHopLimit),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxSalvageCount",
                   "The max salvage count for a single data packet.",
                   UintegerValue (15),
                   MakeUintegerAccessor (&YoungdsrRouting::m_maxSalvageCount),
                   MakeUintegerChecker<uint8_t> ())
    .AddAttribute ("BlacklistTimeout",
                   "The time for a neighbor to stay in blacklist.",
                   TimeValue (Seconds (3)),
                   MakeTimeAccessor (&YoungdsrRouting::m_blacklistTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("GratReplyHoldoff",
                   "The time for gratuitous reply entry to expire.",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&YoungdsrRouting::m_gratReplyHoldoff),
                   MakeTimeChecker ())
    .AddAttribute ("BroadcastJitter",
                   "The jitter time to avoid collision for broadcast packets.",
                   UintegerValue (10),
                   MakeUintegerAccessor (&YoungdsrRouting::m_broadcastJitter),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("LinkAckTimeout",
                   "The time a packet in maintenance buffer wait for "
                   "link acknowledgment.",
                   TimeValue (MilliSeconds (100)),
                   MakeTimeAccessor (&YoungdsrRouting::m_linkAckTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("TryLinkAcks",
                   "The number of link acknowledgment to use.",
                   UintegerValue (1),
                   MakeUintegerAccessor (&YoungdsrRouting::m_tryLinkAcks),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("PassiveAckTimeout",
                   "The time a packet in maintenance buffer wait for "
                   "passive acknowledgment.",
                   TimeValue (MilliSeconds (100)),
                   MakeTimeAccessor (&YoungdsrRouting::m_passiveAckTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("TryPassiveAcks",
                   "The number of passive acknowledgment to use.",
                   UintegerValue (1),
                   MakeUintegerAccessor (&YoungdsrRouting::m_tryPassiveAcks),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RequestPeriod",
                   "The base time interval between route requests.",
                   TimeValue (MilliSeconds (500)),
                   MakeTimeAccessor (&YoungdsrRouting::m_requestPeriod),
                   MakeTimeChecker ())
    .AddAttribute ("MaxRequestPeriod",
                   "The max time interval between route requests.",
                   TimeValue (Seconds (10)),
                   MakeTimeAccessor (&YoungdsrRouting::m_maxRequestPeriod),
                   MakeTimeChecker ())
    .AddAttribute ("GraReplyTableSize",
                   "The gratuitous reply table size.",
                   UintegerValue (64),
                   MakeUintegerAccessor (&YoungdsrRouting::m_graReplyTableSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("CacheType",
                   "Use Link Cache or use Path Cache",
                   StringValue ("LinkCache"),
                   MakeStringAccessor (&YoungdsrRouting::m_cacheType),
                   MakeStringChecker ())
    .AddAttribute ("StabilityDecrFactor",
                   "The stability decrease factor for link cache",
                   UintegerValue (2),
                   MakeUintegerAccessor (&YoungdsrRouting::m_stabilityDecrFactor),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("StabilityIncrFactor",
                   "The stability increase factor for link cache",
                   UintegerValue (4),
                   MakeUintegerAccessor (&YoungdsrRouting::m_stabilityIncrFactor),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("InitStability",
                   "The initial stability factor for link cache",
                   TimeValue (Seconds (25)),
                   MakeTimeAccessor (&YoungdsrRouting::m_initStability),
                   MakeTimeChecker ())
    .AddAttribute ("MinLifeTime",
                   "The minimal life time for link cache",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&YoungdsrRouting::m_minLifeTime),
                   MakeTimeChecker ())
    .AddAttribute ("UseExtends",
                   "The extension time for link cache",
                   TimeValue (Seconds (120)),
                   MakeTimeAccessor (&YoungdsrRouting::m_useExtends),
                   MakeTimeChecker ())
    .AddAttribute ("EnableSubRoute",
                   "Enables saving of sub route when receiving "
                   "route error messages, only available when "
                   "using path route cache",
                   BooleanValue (true),
                   MakeBooleanAccessor (&YoungdsrRouting::m_subRoute),
                   MakeBooleanChecker ())
    .AddAttribute ("RetransIncr",
                   "The increase time for retransmission timer "
                   "when facing network congestion",
                   TimeValue (MilliSeconds (20)),
                   MakeTimeAccessor (&YoungdsrRouting::m_retransIncr),
                   MakeTimeChecker ())
    .AddAttribute ("MaxNetworkQueueSize",
                   "The max number of packet to save in the network queue.",
                   UintegerValue (400),
                   MakeUintegerAccessor (&YoungdsrRouting::m_maxNetworkSize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxNetworkQueueDelay",
                   "The max time for a packet to stay in the network queue.",
                   TimeValue (Seconds (30.0)),
                   MakeTimeAccessor (&YoungdsrRouting::m_maxNetworkDelay),
                   MakeTimeChecker ())
    .AddAttribute ("NumPriorityQueues",
                   "The max number of packet to save in the network queue.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&YoungdsrRouting::m_numPriorityQueues),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("LinkAcknowledgment",
                   "Enable Link layer acknowledgment mechanism",
                   BooleanValue (true),
                   MakeBooleanAccessor (&YoungdsrRouting::m_linkAck),
                   MakeBooleanChecker ())
    .AddTraceSource ("Tx",
                     "Send DSR packet.",
                     MakeTraceSourceAccessor (&YoungdsrRouting::m_txPacketTrace),
                     "ns3::youngdsr::YoungdsrOptionSRHeader::TracedCallback")
    .AddTraceSource ("Drop",
                     "Drop DSR packet",
                     MakeTraceSourceAccessor (&YoungdsrRouting::m_dropTrace),
                     "ns3::Packet::TracedCallback")
  ;
  return tid;
}
  u_int32_t Sendpacketcounter = 0;

YoungdsrRouting::YoungdsrRouting ()
{
  NS_LOG_FUNCTION_NOARGS ();

  m_uniformRandomVariable = CreateObject<UniformRandomVariable> ();

  /*
   * The following Ptr statements created objects for all the options header for DSR, and each of them have
   * distinct option number assigned, when DSR Routing received a packet from higher layer, it will find
   * the following options based on the option number, and pass the packet to the appropriate option to
   * process it. After the option processing, it will pass the packet back to DSR Routing to send down layer.
   */
  Ptr<youngdsr::YoungdsrOptionPad1> pad1Option = CreateObject<youngdsr::YoungdsrOptionPad1> ();
  Ptr<youngdsr::YoungdsrOptionPadn> padnOption = CreateObject<youngdsr::YoungdsrOptionPadn> ();
  Ptr<youngdsr::YoungdsrOptionRreq> rreqOption = CreateObject<youngdsr::YoungdsrOptionRreq> ();
  Ptr<youngdsr::YoungdsrOptionRrep> rrepOption = CreateObject<youngdsr::YoungdsrOptionRrep> ();
  Ptr<youngdsr::YoungdsrOptionSR>   srOption = CreateObject<youngdsr::YoungdsrOptionSR> ();
  Ptr<youngdsr::YoungdsrOptionRerr>   rerrOption = CreateObject<youngdsr::YoungdsrOptionRerr> ();
  Ptr<youngdsr::YoungdsrOptionAckReq> ackReq = CreateObject<youngdsr::YoungdsrOptionAckReq> ();
  Ptr<youngdsr::YoungdsrOptionAck> ack = CreateObject<youngdsr::YoungdsrOptionAck> ();

  Insert (pad1Option);
  Insert (padnOption);
  Insert (rreqOption);
  Insert (rrepOption);
  Insert (srOption);
  Insert (rerrOption);
  Insert (ackReq);
  Insert (ack);

  // Check the send buffer for sending packets
  m_sendBuffTimer.SetFunction (&YoungdsrRouting::SendBuffTimerExpire, this);
  m_sendBuffTimer.Schedule (Seconds (100));
}

YoungdsrRouting::~YoungdsrRouting ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

void
YoungdsrRouting::NotifyNewAggregate ()
{
  NS_LOG_FUNCTION (this << "NotifyNewAggregate");
  if (m_node == 0)
    {
      Ptr<Node> node = this->GetObject<Node> ();
      if (node != 0)
        {
          m_ipv4 = this->GetObject<Ipv4L3Protocol> ();
          if (m_ipv4 != 0)
            {
              this->SetNode (node);
              m_ipv4->Insert (this);
              this->SetDownTarget (MakeCallback (&Ipv4L3Protocol::Send, m_ipv4));
            }

          m_ip = node->GetObject<Ipv4> ();
          if (m_ip != 0)
            {
              NS_LOG_DEBUG ("Ipv4 started");
            }
        }
    }
  IpL4Protocol::NotifyNewAggregate ();
  Simulator::ScheduleNow (&YoungdsrRouting::Start, this);
}

void YoungdsrRouting::Start ()
{
  NS_LOG_FUNCTION (this << "Start DSR Routing protocol");

  NS_LOG_INFO ("The number of network queues " << m_numPriorityQueues);
  for (uint32_t i = 0; i < m_numPriorityQueues; i++)
    {
      // Set the network queue max size and the delay
      NS_LOG_INFO ("The network queue size " << m_maxNetworkSize << " and the queue delay " << m_maxNetworkDelay.GetSeconds ());
      Ptr<youngdsr::YoungdsrNetworkQueue> queue_i = CreateObject<youngdsr::YoungdsrNetworkQueue> (m_maxNetworkSize,m_maxNetworkDelay);
      std::pair<std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator, bool> result_i = m_priorityQueue.insert (std::make_pair (i, queue_i));
      NS_ASSERT_MSG (result_i.second, "Error in creating queues");
    }
  Ptr<youngdsr::YoungdsrRreqTable> rreqTable = CreateObject<youngdsr::YoungdsrRreqTable> ();
  // Set the initial hop limit
  rreqTable->SetInitHopLimit (m_discoveryHopLimit);
  // Configure the request table parameters
  rreqTable->SetRreqTableSize (m_requestTableSize);
  rreqTable->SetRreqIdSize (m_requestTableIds);
  rreqTable->SetUniqueRreqIdSize (m_maxRreqId);
  SetRequestTable (rreqTable);
  // 送信バッファーパラメーターのみを使用してパッシブバッファーパラメーターを設定する
  Ptr<youngdsr::YoungdsrPassiveBuffer> passiveBuffer = CreateObject<youngdsr::YoungdsrPassiveBuffer> ();
  passiveBuffer->SetMaxQueueLen (m_maxSendBuffLen);
  passiveBuffer->SetPassiveBufferTimeout (m_sendBufferTimeout);
  SetPassiveBuffer (passiveBuffer);

  // Set the send buffer parameters
  m_sendBuffer.SetMaxQueueLen (m_maxSendBuffLen);
  m_sendBuffer.SetSendBufferTimeout (m_sendBufferTimeout);
  // Set the error buffer parameters using just the send buffer parameters
  m_errorBuffer.SetMaxQueueLen (m_maxSendBuffLen);
  m_errorBuffer.SetErrorBufferTimeout (m_sendBufferTimeout);
  // Set the maintenance buffer parameters
  m_maintainBuffer.SetMaxQueueLen (m_maxMaintainLen);
  m_maintainBuffer.SetMaintainBufferTimeout (m_maxMaintainTime);
  // Set the gratuitous reply table size
  m_graReply.SetGraTableSize (m_graReplyTableSize);

  if (m_mainAddress == Ipv4Address ())
    {
      Ipv4Address loopback ("127.0.0.1");
      for (uint32_t i = 0; i < m_ipv4->GetNInterfaces (); i++)
        {
          // Use primary address, if multiple
          Ipv4Address addr = m_ipv4->GetAddress (i, 0).GetLocal ();
          m_broadcast = m_ipv4->GetAddress (i, 0).GetBroadcast ();
          if (addr != loopback)
            {
              /*
               * youngdsrルートキャッシュを設定する
               */
              Ptr<youngdsr::YoungdsrRouteCache> routeCache = CreateObject<youngdsr::YoungdsrRouteCache> ();
              // Configure the path cache parameters
              routeCache->SetCacheType (m_cacheType);
              routeCache->SetSubRoute (m_subRoute);
              routeCache->SetMaxCacheLen (m_maxCacheLen);
              routeCache->SetCacheTimeout (m_maxCacheTime);
              routeCache->SetMaxEntriesEachDst (m_maxEntriesEachDst);
              // Parameters for link cache
              routeCache->SetStabilityDecrFactor (m_stabilityDecrFactor);
              routeCache->SetStabilityIncrFactor (m_stabilityIncrFactor);
              routeCache->SetInitStability (m_initStability);
              routeCache->SetMinLifeTime (m_minLifeTime);
              routeCache->SetUseExtends (m_useExtends);
              routeCache->ScheduleTimer ();
              // The call back to handle link error and send error message to appropriate nodes
              /// TODO whether this SendRerrWhenBreaksLinkToNextHop is used or not
              // routeCache->SetCallback (MakeCallback (&YoungdsrRouting::SendRerrWhenBreaksLinkToNextHop, this));
              SetRouteCache (routeCache);
              // Set the main address as the current ip address
              m_mainAddress = addr;

              m_ipv4->GetNetDevice (1)->SetPromiscReceiveCallback (MakeCallback (&YoungdsrRouting::PromiscReceive, this));

              // Allow neighbor manager use this interface for layer 2 feedback if possible
              Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (addr));
              Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice> ();
              if (wifi == 0)
                {
                  break;
                }
              Ptr<WifiMac> mac = wifi->GetMac ();
              if (mac == 0)
                {
                  break;
                }

              routeCache->AddArpCache (m_ipv4->GetInterface (i)->GetArpCache ());
              NS_LOG_LOGIC ("Starting DSR on node " << m_mainAddress);
              break;
            }
        }
      NS_ASSERT (m_mainAddress != Ipv4Address () && m_broadcast != Ipv4Address ());
    }
}

Ptr<NetDevice>
YoungdsrRouting::GetNetDeviceFromContext (std::string context)
{
  // Use "NodeList/*/DeviceList/*/ as reference
  // where element [1] is the Node Id
  // element [2] is the NetDevice Id
  std::vector <std::string> elements = GetElementsFromContext (context);
  Ptr<Node> n = NodeList::GetNode (atoi (elements[1].c_str ()));
  NS_ASSERT (n);
  return n->GetDevice (atoi (elements[3].c_str ()));
}

std::vector<std::string>
YoungdsrRouting::GetElementsFromContext (std::string context)
{
  std::vector <std::string> elements;
  size_t pos1 = 0, pos2;
  while (pos1 != context.npos)
    {
      pos1 = context.find ("/",pos1);
      pos2 = context.find ("/",pos1 + 1);
      elements.push_back (context.substr (pos1 + 1,pos2 - (pos1 + 1)));
      pos1 = pos2;
    }
  return elements;
}

void
YoungdsrRouting::DoDispose (void)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_node = 0;
  for (uint32_t i = 0; i < m_ipv4->GetNInterfaces (); i++)
    {
      // Disable layer 2 link state monitoring (if possible)
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (i);
      Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice> ();
      if (wifi != 0)
        {
          Ptr<WifiMac> mac = wifi->GetMac ()->GetObject<AdhocWifiMac> ();
          if (mac != 0)
            {
              mac->TraceDisconnectWithoutContext ("TxErrHeader",
                                                  m_routeCache->GetTxErrorCallback ());
              m_routeCache->DelArpCache (m_ipv4->GetInterface (i)->GetArpCache ());
            }
        }
    }
  IpL4Protocol::DoDispose ();
}

void
YoungdsrRouting::SetNode (Ptr<Node> node)
{
  // ?? m_nodeはnode idに対応してる
  m_node = node;

}

Ptr<Node>
YoungdsrRouting::GetNode () const
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_node;
}

void YoungdsrRouting::SetRouteCache (Ptr<youngdsr::YoungdsrRouteCache> r)
{
  // / Set the route cache to use
  m_routeCache = r;
}

Ptr<youngdsr::YoungdsrRouteCache>
YoungdsrRouting::GetRouteCache () const
{
  // / Get the route cache to use
  return m_routeCache;
}

void YoungdsrRouting::SetRequestTable (Ptr<youngdsr::YoungdsrRreqTable> q)
{
  // / Set the request table to use
  m_rreqTable = q;
}

Ptr<youngdsr::YoungdsrRreqTable>
YoungdsrRouting::GetRequestTable () const
{
  // / Get the request table to use
  return m_rreqTable;
}

void YoungdsrRouting::SetPassiveBuffer (Ptr<youngdsr::YoungdsrPassiveBuffer> p)
{
  // / Set the request table to use
  m_passiveBuffer = p;
}

Ptr<youngdsr::YoungdsrPassiveBuffer>
YoungdsrRouting::GetPassiveBuffer () const
{
  // / Get the request table to use
  return m_passiveBuffer;
}

Ptr<Node>
YoungdsrRouting::GetNodeWithAddress (Ipv4Address ipv4Address)
{
  NS_LOG_FUNCTION (this << ipv4Address);
  int32_t nNodes = NodeList::GetNNodes ();
  for (int32_t i = 0; i < nNodes; ++i)
    {

      Ptr<Node> node = NodeList::GetNode (i);
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      int32_t ifIndex = ipv4->GetInterfaceForAddress (ipv4Address);
      if (ifIndex != -1)
        {
          return node;
        }
    }
  return 0;
}

bool YoungdsrRouting::IsLinkCache ()
{
  return m_routeCache->IsLinkCache ();
}

void YoungdsrRouting::UseExtends (YoungdsrRouteCacheEntry::IP_VECTOR rt)
{
  m_routeCache->UseExtends (rt);
}

bool YoungdsrRouting::LookupRoute (Ipv4Address id, YoungdsrRouteCacheEntry & rt)
{
  return m_routeCache->LookupRoute (id, rt);
}

bool YoungdsrRouting::AddRoute_Link (YoungdsrRouteCacheEntry::IP_VECTOR nodelist, Ipv4Address source)
{
  Ipv4Address nextHop = SearchNextHop (source, nodelist);
  m_errorBuffer.DropPacketForErrLink (source, nextHop);
  return m_routeCache->AddRoute_Link (nodelist, source);
}

bool YoungdsrRouting::AddRoute (YoungdsrRouteCacheEntry & rt)
{
  std::vector<Ipv4Address> nodelist = rt.GetVector ();
  Ipv4Address nextHop = SearchNextHop (m_mainAddress, nodelist);
  m_errorBuffer.DropPacketForErrLink (m_mainAddress, nextHop);
  return m_routeCache->AddRoute (rt);
}

void YoungdsrRouting::DeleteAllRoutesIncludeLink (Ipv4Address errorSrc, Ipv4Address unreachNode, Ipv4Address node)
{
  m_routeCache->DeleteAllRoutesIncludeLink (errorSrc, unreachNode, node);
}

bool YoungdsrRouting::UpdateRouteEntry (Ipv4Address dst)
{
  return m_routeCache->UpdateRouteEntry (dst);
}

bool YoungdsrRouting::FindSourceEntry (Ipv4Address src, Ipv4Address dst, uint16_t id)
{
  return m_rreqTable->FindSourceEntry (src, dst, id);
}

Ipv4Address
YoungdsrRouting::GetIPfromMAC (Mac48Address address)
{
  NS_LOG_FUNCTION (this << address);
  int32_t nNodes = NodeList::GetNNodes ();
  for (int32_t i = 0; i < nNodes; ++i)
    {
      Ptr<Node> node = NodeList::GetNode (i);
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      Ptr<NetDevice> netDevice = ipv4->GetNetDevice (1);

      if (netDevice->GetAddress () == address)
        {
          return ipv4->GetAddress (1, 0).GetLocal ();
        }
    }
  return 0;
}

void YoungdsrRouting::PrintVector (std::vector<Ipv4Address>& vec)
{
  NS_LOG_FUNCTION (this);
  /*
   * Check elements in a route vector
   */
  if (!vec.size ())
    {
      NS_LOG_DEBUG ("The vector is empty");
    }
  else
    {
      NS_LOG_DEBUG ("Print all the elements in a vector");
      for (std::vector<Ipv4Address>::const_iterator i = vec.begin (); i != vec.end (); ++i)
        {
          NS_LOG_DEBUG ("The ip address " << *i);
        }
    }
}

Ipv4Address YoungdsrRouting::SearchNextHop (Ipv4Address ipv4Address, std::vector<Ipv4Address>& vec)
{
  NS_LOG_FUNCTION (this << ipv4Address);
  Ipv4Address nextHop;
  NS_LOG_DEBUG ("the vector size " << vec.size ());
  if (vec.size () == 2)
    {
      NS_LOG_DEBUG ("The two nodes are neighbors");
      nextHop = vec[1];
      return nextHop;
    }
  else
    {
      if (ipv4Address == vec.back ())
        {
          NS_LOG_DEBUG ("We have reached to the final destination " << ipv4Address << " " << vec.back ());
          return ipv4Address;
        }
      for (std::vector<Ipv4Address>::const_iterator i = vec.begin (); i != vec.end (); ++i)
        {
          if (ipv4Address == (*i))
            {
              nextHop = *(++i);
              return nextHop;
            }
        }
    }
  NS_LOG_DEBUG ("Next hop address not found");
  Ipv4Address none = "0.0.0.0";
  return none;
}

Ptr<Ipv4Route>
YoungdsrRouting::SetRoute (Ipv4Address nextHop, Ipv4Address srcAddress)
{
  NS_LOG_FUNCTION (this << nextHop << srcAddress);
  m_ipv4Route = Create<Ipv4Route> ();
  m_ipv4Route->SetDestination (nextHop);
  m_ipv4Route->SetGateway (nextHop);
  m_ipv4Route->SetSource (srcAddress);
  return m_ipv4Route;
}

int
YoungdsrRouting::GetProtocolNumber (void) const
{
  // / This is the protocol number for DSR which is 48
  return PROT_NUMBER;
}

uint16_t
YoungdsrRouting::GetIDfromIP (Ipv4Address address)
{
  int32_t nNodes = NodeList::GetNNodes ();
  for (int32_t i = 0; i < nNodes; ++i)
    {
      Ptr<Node> node = NodeList::GetNode (i);
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      if (ipv4->GetAddress (1, 0).GetLocal () == address)
        {
          return uint16_t (i);
        }
    }
  return 256;
}

Ipv4Address
YoungdsrRouting::GetIPfromID (uint16_t id)
{
  if (id >= 256)
    {
      NS_LOG_DEBUG ("Exceed the node range");
      return "0.0.0.0";
    }
  else
    {
      Ptr<Node> node = NodeList::GetNode (uint32_t (id));
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      return ipv4->GetAddress (1, 0).GetLocal ();
    }
}

uint32_t
YoungdsrRouting::GetPriority (YoungdsrMessageType messageType)
{
  if (messageType == DSR_CONTROL_PACKET)
    {
      return 0;
    }
  else
    {
      return 1;
    }
}

void YoungdsrRouting::SendBuffTimerExpire ()
{
  if (m_sendBuffTimer.IsRunning ())
    {
      m_sendBuffTimer.Cancel ();
    }
  m_sendBuffTimer.Schedule (m_sendBuffInterval);
  CheckSendBuffer ();
}

void YoungdsrRouting::CheckSendBuffer ()
{
  NS_LOG_INFO (Simulator::Now ().GetSeconds ()
               << " Checking send buffer at " << m_mainAddress << " with size " << m_sendBuffer.GetSize ());


  for (std::vector<YoungdsrSendBuffEntry>::iterator i = m_sendBuffer.GetBuffer ().begin (); i != m_sendBuffer.GetBuffer ().end (); )
    {
      NS_LOG_DEBUG ("Here we try to find the data packet in the send buffer");
      Ipv4Address destination = i->GetDestination ();
      YoungdsrRouteCacheEntry toDst;
      bool findRoute = m_routeCache->LookupRoute (destination, toDst);
      if (findRoute)
        {
          NS_LOG_INFO ("We have found a route for the packet");
          Ptr<const Packet> packet = i->GetPacket ();
          Ptr<Packet> cleanP = packet->Copy ();
          uint8_t protocol = i->GetProtocol ();

          i = m_sendBuffer.GetBuffer ().erase (i);

          YoungdsrRoutingHeader youngdsrRoutingHeader;
          Ptr<Packet> copyP = packet->Copy ();
          Ptr<Packet> youngdsrPacket = packet->Copy ();
          youngdsrPacket->RemoveHeader (youngdsrRoutingHeader);
          uint32_t offset = youngdsrRoutingHeader.GetYoungdsrOptionsOffset ();
          copyP->RemoveAtStart (offset); // Here the processed size is 8 bytes, which is the fixed sized extension header
          // The packet to get ipv4 header
          Ptr<Packet> ipv4P = copyP->Copy ();
          /*
           * Peek data to get the option type as well as length and segmentsLeft field
           */
          uint32_t size = copyP->GetSize ();
          uint8_t *data = new uint8_t[size];
          copyP->CopyData (data, size);

          uint8_t optionType = 0;
          optionType = *(data);

          if (optionType == 3)
            {
              Ptr<youngdsr::YoungdsrOptions> youngdsrOption;
              YoungdsrOptionHeader youngdsrOptionHeader;
              uint8_t errorType = *(data + 2);

              if (errorType == 1) // This is the Route Error Option
                {
                  YoungdsrOptionRerrUnreachHeader rerr;
                  copyP->RemoveHeader (rerr);
                  NS_ASSERT (copyP->GetSize () == 0);

                  YoungdsrOptionRerrUnreachHeader newUnreach;
                  newUnreach.SetErrorType (1);
                  newUnreach.SetErrorSrc (rerr.GetErrorSrc ());
                  newUnreach.SetUnreachNode (rerr.GetUnreachNode ());
                  newUnreach.SetErrorDst (rerr.GetErrorDst ());
                  newUnreach.SetSalvage (rerr.GetSalvage ()); // Set the value about whether to salvage a packet or not

                  YoungdsrOptionSRHeader sourceRoute;
                  std::vector<Ipv4Address> errorRoute = toDst.GetVector ();
                  sourceRoute.SetNodesAddress (errorRoute);
                  /// When found a route and use it, UseExtends to the link cache
                  if (m_routeCache->IsLinkCache ())
                    {
                      m_routeCache->UseExtends (errorRoute);
                    }
                  sourceRoute.SetSegmentsLeft ((errorRoute.size () - 2));
                  uint8_t salvage = 0;
                  sourceRoute.SetSalvage (salvage);
                  Ipv4Address nextHop = SearchNextHop (m_mainAddress, errorRoute); // Get the next hop address

                  if (nextHop == "0.0.0.0")
                    {
                      PacketNewRoute (youngdsrPacket, m_mainAddress, destination, protocol);
                      return;
                    }

                  SetRoute (nextHop, m_mainAddress);
                  uint8_t length = (sourceRoute.GetLength () + newUnreach.GetLength ());
                  youngdsrRoutingHeader.SetNextHeader (protocol);
                  youngdsrRoutingHeader.SetMessageType (1);
                  youngdsrRoutingHeader.SetSourceId (GetIDfromIP (m_mainAddress));
                  youngdsrRoutingHeader.SetDestId (255);
                  youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 4);
                  youngdsrRoutingHeader.AddYoungdsrOption (newUnreach);
                  youngdsrRoutingHeader.AddYoungdsrOption (sourceRoute);

                  Ptr<Packet> newPacket = Create<Packet> ();
                  newPacket->AddHeader (youngdsrRoutingHeader); // Add the routing header with rerr and sourceRoute attached to it
                  Ptr<NetDevice> dev = m_ip->GetNetDevice (m_ip->GetInterfaceForAddress (m_mainAddress));
                  m_ipv4Route->SetOutputDevice (dev);

                  uint32_t priority = GetPriority (DSR_CONTROL_PACKET); /// This will be priority 0

                  std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator i = m_priorityQueue.find (priority);
                  Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = i->second;
                  NS_LOG_LOGIC ("Will be inserting into priority queue number: " << priority);

                  //m_downTarget (newPacket, m_mainAddress, nextHop, GetProtocolNumber (), m_ipv4Route);

                  /// \todo New YoungdsrNetworkQueueEntry
                  YoungdsrNetworkQueueEntry newEntry (newPacket, m_mainAddress, nextHop, Simulator::Now (), m_ipv4Route);

                  if (youngdsrNetworkQueue->Enqueue (newEntry))
                    {
                      Scheduler (priority);
                    }
                  else
                    {
                      NS_LOG_INFO ("Packet dropped as youngdsr network queue is full");
                    }
                }
            }
          else
            {
              youngdsrRoutingHeader.SetNextHeader (protocol);
              youngdsrRoutingHeader.SetMessageType (2);
              youngdsrRoutingHeader.SetSourceId (GetIDfromIP (m_mainAddress));
              youngdsrRoutingHeader.SetDestId (GetIDfromIP (destination));

              YoungdsrOptionSRHeader sourceRoute;
              std::vector<Ipv4Address> nodeList = toDst.GetVector (); // Get the route from the route entry we found
              Ipv4Address nextHop = SearchNextHop (m_mainAddress, nodeList);  // Get the next hop address for the route
              if (nextHop == "0.0.0.0")
                {
                  PacketNewRoute (youngdsrPacket, m_mainAddress, destination, protocol);
                  return;
                }
              uint8_t salvage = 0;
              sourceRoute.SetNodesAddress (nodeList); // Save the whole route in the source route header of the packet
              sourceRoute.SetSegmentsLeft ((nodeList.size () - 2)); // The segmentsLeft field will indicate the hops to go
              sourceRoute.SetSalvage (salvage);
              /// When found a route and use it, UseExtends to the link cache
              if (m_routeCache->IsLinkCache ())
                {
                  m_routeCache->UseExtends (nodeList);
                }
              uint8_t length = sourceRoute.GetLength ();
              youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 2);
              youngdsrRoutingHeader.AddYoungdsrOption (sourceRoute);
              cleanP->AddHeader (youngdsrRoutingHeader);
              Ptr<const Packet> mtP = cleanP->Copy ();
              // Put the data packet in the maintenance queue for data packet retransmission
              YoungdsrMaintainBuffEntry newEntry (/*Packet=*/ mtP, /*Ipv4Address=*/ m_mainAddress, /*nextHop=*/ nextHop,
                                                      /*source=*/ m_mainAddress, /*destination=*/ destination, /*ackId=*/ 0,
                                                      /*SegsLeft=*/ nodeList.size () - 2, /*expire time=*/ m_maxMaintainTime);
              bool result = m_maintainBuffer.Enqueue (newEntry); // Enqueue the packet the the maintenance buffer
              if (result)
                {
                  NetworkKey networkKey;
                  networkKey.m_ackId = newEntry.GetAckId ();
                  networkKey.m_ourAdd = newEntry.GetOurAdd ();
                  networkKey.m_nextHop = newEntry.GetNextHop ();
                  networkKey.m_source = newEntry.GetSrc ();
                  networkKey.m_destination = newEntry.GetDst ();

                  PassiveKey passiveKey;
                  passiveKey.m_ackId = 0;
                  passiveKey.m_source = newEntry.GetSrc ();
                  passiveKey.m_destination = newEntry.GetDst ();
                  passiveKey.m_segsLeft = newEntry.GetSegsLeft ();

                  LinkKey linkKey;
                  linkKey.m_source = newEntry.GetSrc ();
                  linkKey.m_destination = newEntry.GetDst ();
                  linkKey.m_ourAdd = newEntry.GetOurAdd ();
                  linkKey.m_nextHop = newEntry.GetNextHop ();

                  m_addressForwardCnt[networkKey] = 0;
                  m_passiveCnt[passiveKey] = 0;
                  m_linkCnt[linkKey] = 0;

                  if (m_linkAck)
                    {
                      ScheduleLinkPacketRetry (newEntry, protocol);
                    }
                  else
                    {
                      NS_LOG_LOGIC ("Not using link acknowledgment");
                      if (nextHop != destination)
                        {
                          SchedulePassivePacketRetry (newEntry, protocol);
                        }
                      else
                        {
                          // This is the first network retry
                          ScheduleNetworkPacketRetry (newEntry, true, protocol);
                        }
                    }
                }
              // we need to suspend the normal timer that checks the send buffer
              // until we are done sending packets
              if (!m_sendBuffTimer.IsSuspended ())
                {
                  m_sendBuffTimer.Suspend ();
                }
              Simulator::Schedule (m_sendBuffInterval, &YoungdsrRouting::SendBuffTimerExpire, this);
              return;
            }
        }
      else
        {
          ++i;
        }
    }
  //after going through the entire send buffer and send all packets found route,
  //we need to resume the timer if it has been suspended
  if (m_sendBuffTimer.IsSuspended ())
    {
      NS_LOG_DEBUG ("Resume the send buffer timer");
      m_sendBuffTimer.Resume ();
    }
}

bool YoungdsrRouting::PromiscReceive (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol, const Address &from,
                                 const Address &to, NetDevice::PacketType packetType)
{

  if (protocol != Ipv4L3Protocol::PROT_NUMBER)
    {
      return false;
    }
  // Remove the ipv4 header here
  Ptr<Packet> pktMinusIpHdr = packet->Copy ();
  Ipv4Header ipv4Header;
  pktMinusIpHdr->RemoveHeader (ipv4Header);

  if (ipv4Header.GetProtocol () != YoungdsrRouting::PROT_NUMBER)
    {
      return false;
    }
  // Remove the youngdsr routing header here
  Ptr<Packet> pktMinusYoungdsrHdr = pktMinusIpHdr->Copy ();
  YoungdsrRoutingHeader youngdsrRouting;
  pktMinusYoungdsrHdr->RemoveHeader (youngdsrRouting);

  /*
   * メッセージタイプ2はデータパケットを意味します。データをさらに処理します
    *配信通知用のパケット、安全に制御パケットを無視
    *ここでの別のチェックは、自分の住所です。これが宛先のデータである場合、
    *さらに処理します。それ以外の場合は、無視します
   */
  Ipv4Address ourAddress = m_ipv4->GetAddress (1, 0).GetLocal ();
  // check if the message type is 2 and if the ipv4 address matches
  if (youngdsrRouting.GetMessageType () == 2 && ourAddress == m_mainAddress)
    {
      NS_LOG_DEBUG ("data packet receives " << packet->GetUid ());
      Ipv4Address sourceIp = GetIPfromID (youngdsrRouting.GetSourceId ());
      Ipv4Address destinationIp = GetIPfromID ( youngdsrRouting.GetDestId ());
      /// これは、データパケットを受信したばかりのIPアドレスです
      Ipv4Address previousHop = GetIPfromMAC (Mac48Address::ConvertFrom (from));

      Ptr<Packet> p = Create<Packet> ();
      // ここで、セグメントの左の値は、バッファエントリを維持する前のホップをチェックするために1を足す必要があります。
      YoungdsrMaintainBuffEntry newEntry;
      newEntry.SetPacket (p);
      newEntry.SetSrc (sourceIp);
      newEntry.SetDst (destinationIp);
      /// これは前のノードのエントリであることを忘れないでください
      newEntry.SetOurAdd (previousHop);
      newEntry.SetNextHop (ourAddress);
      /// 前のノードのメンテナンスバッファーとパッシブackを取得します
      Ptr<Node> node = GetNodeWithAddress (previousHop);
      NS_LOG_DEBUG ("The previous node " << previousHop);

      Ptr<youngdsr::YoungdsrRouting> youngdsr = node->GetObject<youngdsr::YoungdsrRouting> ();
      youngdsr->CancelLinkPacketTimer (newEntry);
    }

  // IPパケットと他のホスト宛のパケットのみを受信します
  if (packetType == NetDevice::PACKET_OTHERHOST)
    {
      //just to minimize debug output
      NS_LOG_INFO (this << from << to << packetType << *pktMinusIpHdr);

      uint8_t offset = youngdsrRouting.GetYoungdsrOptionsOffset ();        // オプションヘッダーのオフセット（この場合は4バイト）を取得します
      uint8_t nextHeader = youngdsrRouting.GetNextHeader ();
      uint32_t sourceId = youngdsrRouting.GetSourceId ();
      Ipv4Address source = GetIPfromID (sourceId);

      // This packet is used to peek option type
      pktMinusIpHdr->RemoveAtStart (offset);
      /*
       * データをピークして、オプションタイプと長さおよびセグメントの左フィールドを取得します。
       */
      uint32_t size = pktMinusIpHdr->GetSize ();
      uint8_t *data = new uint8_t[size];
      pktMinusIpHdr->CopyData (data, size);
      uint8_t optionType = 0;
      optionType = *(data);

      Ptr<youngdsr::YoungdsrOptions> youngdsrOption;
      if (optionType == 96)        // This is the source route option
        {
          Ipv4Address promiscSource = GetIPfromMAC (Mac48Address::ConvertFrom (from));
          youngdsrOption = GetOption (optionType);       // Get the relative DSR option and demux to the process function
         //オーバーヒアリング機能
          NS_LOG_DEBUG (Simulator::Now ().GetSeconds () <<
                        " DSR node " << m_mainAddress <<
                        " overhearing packet PID: " << pktMinusIpHdr->GetUid () <<
                        " from " << promiscSource <<
                        " to " << GetIPfromMAC (Mac48Address::ConvertFrom (to)) <<
                        " with source IP " << ipv4Header.GetSource () <<
                        " and destination IP " << ipv4Header.GetDestination () <<
                        " and packet : " << *pktMinusYoungdsrHdr);
/*
outputfile2 << Simulator::Now ().GetMicroSeconds () <<
              " DSR node " << m_mainAddress <<
              " overhearing packet PID: " << pktMinusIpHdr->GetUid () <<
              " from " << promiscSource <<
              " to " << GetIPfromMAC (Mac48Address::ConvertFrom (to)) <<
              " with source IP " << ipv4Header.GetSource () <<
              " and destination IP " << ipv4Header.GetDestination () <<
              " and packet : " << *pktMinusYoungdsrHdr << '\n';
*/
          bool isPromisc = true;                     // Set the boolean value isPromisc as true
          youngdsrOption->Process (pktMinusIpHdr, pktMinusYoungdsrHdr, m_mainAddress, source, ipv4Header, nextHeader, isPromisc, promiscSource);
          return true;

        }
    }
  return false;
}

void
YoungdsrRouting::PacketNewRoute (Ptr<Packet> packet,
                            Ipv4Address source,
                            Ipv4Address destination,
                            uint8_t protocol)
{
  NS_LOG_FUNCTION (this << packet << source << destination << (uint32_t)protocol);
  // 特定の宛先のルートを検索する
  YoungdsrRouteCacheEntry toDst;
  bool findRoute = m_routeCache->LookupRoute (destination, toDst);
  // 既存のルートがない場合、パケットをキューに入れる
  if (!findRoute)
    {
      NS_LOG_INFO (Simulator::Now ().GetSeconds ()
                   << "s " << m_mainAddress << " there is no route for this packet, queue the packet");

      Ptr<Packet> p = packet->Copy ();
      YoungdsrSendBuffEntry newEntry (p, destination, m_sendBufferTimeout, protocol);     // 送信バッファの新しいエントリを作成します
      bool result = m_sendBuffer.Enqueue (newEntry);     // パケットを送信バッファーに入れます
      if (result)
        {
          NS_LOG_INFO (Simulator::Now ().GetSeconds ()
                       << "s Add packet PID: " << packet->GetUid () << " to queue. Packet: " << *packet);

          NS_LOG_LOGIC ("Send RREQ to" << destination);
          if ((m_addressReqTimer.find (destination) == m_addressReqTimer.end ()) && (m_nonPropReqTimer.find (destination) == m_nonPropReqTimer.end ()))
            {
              /*
               * リクエスト送信機能を呼び出すと、リクエストテーブルエントリとttlが更新されます
               */
              SendInitialRequest (source, destination, protocol);
            }
        }
    }
  else
    {
      Ptr<Packet> cleanP = packet->Copy ();
      YoungdsrRoutingHeader youngdsrRoutingHeader;
      youngdsrRoutingHeader.SetNextHeader (protocol);
      youngdsrRoutingHeader.SetMessageType (2);
      youngdsrRoutingHeader.SetSourceId (GetIDfromIP (source));
      youngdsrRoutingHeader.SetDestId (GetIDfromIP (destination));

      YoungdsrOptionSRHeader sourceRoute;
      std::vector<Ipv4Address> nodeList = toDst.GetVector ();     // 見つけたルートエントリからルートを取得します
      Ipv4Address nextHop = SearchNextHop (m_mainAddress, nodeList);      // ルートの次ホップアドレスを取得します
      if (nextHop == "0.0.0.0")
        {
          PacketNewRoute (cleanP, source, destination, protocol);
          return;
        }
      uint8_t salvage = 0;
      sourceRoute.SetNodesAddress (nodeList);     // パケットのソースルートヘッダーにルート全体を保存します
      //ルートを見つけて使用すると、リンクキャッシュへのUseExtends
      if (m_routeCache->IsLinkCache ())
        {
          m_routeCache->UseExtends (nodeList);
        }
      sourceRoute.SetSegmentsLeft ((nodeList.size () - 2));     // The segmentsLeft field will indicate the hops to go
      sourceRoute.SetSalvage (salvage);

      uint8_t length = sourceRoute.GetLength ();
      youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 2);
      youngdsrRoutingHeader.AddYoungdsrOption (sourceRoute);
      cleanP->AddHeader (youngdsrRoutingHeader);
      Ptr<const Packet> mtP = cleanP->Copy ();
      SetRoute (nextHop, m_mainAddress);
      // Put the data packet in the maintenance queue for data packet retransmission
      YoungdsrMaintainBuffEntry newEntry (/*Packet=*/ mtP, /*Ipv4Address=*/ m_mainAddress, /*nextHop=*/ nextHop,
                                              /*source=*/ source, /*destination=*/ destination, /*ackId=*/ 0,
                                              /*SegsLeft=*/ nodeList.size () - 2, /*expire time=*/ m_maxMaintainTime);
      bool result = m_maintainBuffer.Enqueue (newEntry);     // Enqueue the packet the the maintenance buffer

      if (result)
        {
          NetworkKey networkKey;
          networkKey.m_ackId = newEntry.GetAckId ();
          networkKey.m_ourAdd = newEntry.GetOurAdd ();
          networkKey.m_nextHop = newEntry.GetNextHop ();
          networkKey.m_source = newEntry.GetSrc ();
          networkKey.m_destination = newEntry.GetDst ();

          PassiveKey passiveKey;
          passiveKey.m_ackId = 0;
          passiveKey.m_source = newEntry.GetSrc ();
          passiveKey.m_destination = newEntry.GetDst ();
          passiveKey.m_segsLeft = newEntry.GetSegsLeft ();

          LinkKey linkKey;
          linkKey.m_source = newEntry.GetSrc ();
          linkKey.m_destination = newEntry.GetDst ();
          linkKey.m_ourAdd = newEntry.GetOurAdd ();
          linkKey.m_nextHop = newEntry.GetNextHop ();

          m_addressForwardCnt[networkKey] = 0;
          m_passiveCnt[passiveKey] = 0;
          m_linkCnt[linkKey] = 0;

          if (m_linkAck)
            {
              ScheduleLinkPacketRetry (newEntry, protocol);
            }
          else
            {
              NS_LOG_LOGIC ("Not using link acknowledgment");
              if (nextHop != destination)
                {
                  SchedulePassivePacketRetry (newEntry, protocol);
                }
              else
                {
                  // This is the first network retry
                  ScheduleNetworkPacketRetry (newEntry, true, protocol);
                }
            }
        }
    }
}

void
YoungdsrRouting::SendUnreachError (Ipv4Address unreachNode, Ipv4Address destination, Ipv4Address originalDst, uint8_t salvage, uint8_t protocol)
{
  NS_LOG_FUNCTION (this << unreachNode << destination << originalDst << (uint32_t)salvage << (uint32_t)protocol);
  YoungdsrRoutingHeader youngdsrRoutingHeader;
  youngdsrRoutingHeader.SetNextHeader (protocol);
  youngdsrRoutingHeader.SetMessageType (1);
  youngdsrRoutingHeader.SetSourceId (GetIDfromIP (m_mainAddress));
  youngdsrRoutingHeader.SetDestId (GetIDfromIP (destination));

  YoungdsrOptionRerrUnreachHeader rerrUnreachHeader;
  rerrUnreachHeader.SetErrorType (1);
  rerrUnreachHeader.SetErrorSrc (m_mainAddress);
  rerrUnreachHeader.SetUnreachNode (unreachNode);
  rerrUnreachHeader.SetErrorDst (destination);
  rerrUnreachHeader.SetOriginalDst (originalDst);
  rerrUnreachHeader.SetSalvage (salvage);                       // Set the value about whether to salvage a packet or not
  uint8_t rerrLength = rerrUnreachHeader.GetLength ();


  YoungdsrRouteCacheEntry toDst;
  bool findRoute = m_routeCache->LookupRoute (destination, toDst);
  // Queue the packet if there is no route pre-existing
  Ptr<Packet> newPacket = Create<Packet> ();
  if (!findRoute)
    {
      if (destination == m_mainAddress)
        {
          NS_LOG_INFO ("We are the error source, send request to original dst " << originalDst);
          // Send error request message if we are the source node
          SendErrorRequest (rerrUnreachHeader, protocol);
        }
      else
        {
          NS_LOG_INFO (Simulator::Now ().GetSeconds ()
                       << "s " << m_mainAddress << " there is no route for this packet, queue the packet");

          youngdsrRoutingHeader.SetPayloadLength (rerrLength + 2);
          youngdsrRoutingHeader.AddYoungdsrOption (rerrUnreachHeader);
          newPacket->AddHeader (youngdsrRoutingHeader);
          Ptr<Packet> p = newPacket->Copy ();
          // Save the error packet in the error buffer
          YoungdsrErrorBuffEntry newEntry (p, destination, m_mainAddress, unreachNode, m_sendBufferTimeout, protocol);
          bool result = m_errorBuffer.Enqueue (newEntry);                  // Enqueue the packet in send buffer
          if (result)
            {
              NS_LOG_INFO (Simulator::Now ().GetSeconds ()
                           << "s Add packet PID: " << p->GetUid () << " to queue. Packet: " << *p);
              NS_LOG_LOGIC ("Send RREQ to" << destination);
              if ((m_addressReqTimer.find (destination) == m_addressReqTimer.end ()) && (m_nonPropReqTimer.find (destination) == m_nonPropReqTimer.end ()))
                {
                  NS_LOG_DEBUG ("When there is no existing route request for " << destination << ", initialize one");
                  /*
                   * Call the send request function, it will update the request table entry and ttl there
                   */
                  SendInitialRequest (m_mainAddress, destination, protocol);
                }
            }
        }
    }
  else
    {
      std::vector<Ipv4Address> nodeList = toDst.GetVector ();
      Ipv4Address nextHop = SearchNextHop (m_mainAddress, nodeList);
      if (nextHop == "0.0.0.0")
        {
          NS_LOG_DEBUG ("The route is not right");
          PacketNewRoute (newPacket, m_mainAddress, destination, protocol);
          return;
        }
      YoungdsrOptionSRHeader sourceRoute;
      sourceRoute.SetNodesAddress (nodeList);
      /// When found a route and use it, UseExtends to the link cache
      if (m_routeCache->IsLinkCache ())
        {
          m_routeCache->UseExtends (nodeList);
        }
      sourceRoute.SetSegmentsLeft ((nodeList.size () - 2));
      uint8_t srLength = sourceRoute.GetLength ();
      uint8_t length = (srLength + rerrLength);

      youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 4);
      youngdsrRoutingHeader.AddYoungdsrOption (rerrUnreachHeader);
      youngdsrRoutingHeader.AddYoungdsrOption (sourceRoute);
      newPacket->AddHeader (youngdsrRoutingHeader);

      SetRoute (nextHop, m_mainAddress);
      Ptr<NetDevice> dev = m_ip->GetNetDevice (m_ip->GetInterfaceForAddress (m_mainAddress));
      m_ipv4Route->SetOutputDevice (dev);
      NS_LOG_INFO ("Send the packet to the next hop address " << nextHop << " from " << m_mainAddress << " with the size " << newPacket->GetSize ());

      uint32_t priority = GetPriority (DSR_CONTROL_PACKET);
      std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator i = m_priorityQueue.find (priority);
      Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = i->second;
      NS_LOG_DEBUG ("Will be inserting into priority queue " << youngdsrNetworkQueue << " number: " << priority);

      //m_downTarget (newPacket, m_mainAddress, nextHop, GetProtocolNumber (), m_ipv4Route);

      /// \todo New YoungdsrNetworkQueueEntry
      YoungdsrNetworkQueueEntry newEntry (newPacket, m_mainAddress, nextHop, Simulator::Now (), m_ipv4Route);

      if (youngdsrNetworkQueue->Enqueue (newEntry))
        {
          Scheduler (priority);
        }
      else
        {
          NS_LOG_INFO ("Packet dropped as youngdsr network queue is full");
        }
    }
}

void
YoungdsrRouting::ForwardErrPacket (YoungdsrOptionRerrUnreachHeader &rerr,
                              YoungdsrOptionSRHeader &sourceRoute,
                              Ipv4Address nextHop,
                              uint8_t protocol,
                              Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this << rerr << sourceRoute << nextHop << (uint32_t)protocol << route);
  NS_ASSERT_MSG (!m_downTarget.IsNull (), "Error, YoungdsrRouting cannot send downward");
  YoungdsrRoutingHeader youngdsrRoutingHeader;
  youngdsrRoutingHeader.SetNextHeader (protocol);
  youngdsrRoutingHeader.SetMessageType (1);
  youngdsrRoutingHeader.SetSourceId (GetIDfromIP (rerr.GetErrorSrc ()));
  youngdsrRoutingHeader.SetDestId (GetIDfromIP (rerr.GetErrorDst ()));

  uint8_t length = (sourceRoute.GetLength () + rerr.GetLength ());
  youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 4);
  youngdsrRoutingHeader.AddYoungdsrOption (rerr);
  youngdsrRoutingHeader.AddYoungdsrOption (sourceRoute);
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (youngdsrRoutingHeader);
  Ptr<NetDevice> dev = m_ip->GetNetDevice (m_ip->GetInterfaceForAddress (m_mainAddress));
  route->SetOutputDevice (dev);

  uint32_t priority = GetPriority (DSR_CONTROL_PACKET);
  std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator i = m_priorityQueue.find (priority);
  Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = i->second;
  NS_LOG_DEBUG ("Will be inserting into priority queue " << youngdsrNetworkQueue << " number: " << priority);

  //m_downTarget (packet, m_mainAddress, nextHop, GetProtocolNumber (), route);

  /// \todo New YoungdsrNetworkQueueEntry
  YoungdsrNetworkQueueEntry newEntry (packet, m_mainAddress, nextHop, Simulator::Now (), route);

  if (youngdsrNetworkQueue->Enqueue (newEntry))
    {
      Scheduler (priority);
    }
  else
    {
      NS_LOG_INFO ("Packet dropped as youngdsr network queue is full");
    }
}

void
YoungdsrRouting::Send (Ptr<Packet> packet,
                  Ipv4Address source,
                  Ipv4Address destination,
                  uint8_t protocol,
                  Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this << packet << source << destination << (uint32_t)protocol << route);
  NS_ASSERT_MSG (!m_downTarget.IsNull (), "Error, YoungdsrRouting cannot send downward");

  if (protocol == 1)
    {
      NS_LOG_INFO ("Drop packet. Not handling ICMP packet for now");
    }
  else
    {
      // Look up routes for the specific destination
      YoungdsrRouteCacheEntry toDst;
      bool findRoute = m_routeCache->LookupRoute (destination, toDst);
      // Queue the packet if there is no route pre-existing
      if (!findRoute)
        {
          NS_LOG_INFO (Simulator::Now ().GetSeconds ()
                       << "s " << m_mainAddress << " there is no route for this packet, queue the packet");

          Ptr<Packet> p = packet->Copy ();
          YoungdsrSendBuffEntry newEntry (p, destination, m_sendBufferTimeout, protocol);     // Create a new entry for send buffer
          bool result = m_sendBuffer.Enqueue (newEntry);     // Enqueue the packet in send buffer
          if (result)
            {
              NS_LOG_INFO (Simulator::Now ().GetSeconds ()
                           << "s Add packet PID: " << packet->GetUid () << " to send buffer. Packet: " << *packet);
              // Only when there is no existing route request timer when new route request is scheduled
              if ((m_addressReqTimer.find (destination) == m_addressReqTimer.end ()) && (m_nonPropReqTimer.find (destination) == m_nonPropReqTimer.end ()))
                {
                  /*
                   * Call the send request function, it will update the request table entry and ttl value
                   */
                  NS_LOG_LOGIC ("Send initial RREQ to " << destination);
                  SendInitialRequest (source, destination, protocol);
                }
              else
                {
                  NS_LOG_LOGIC ("There is existing route request timer with request count " << m_rreqTable->GetRreqCnt (destination));
                }
            }
        }
      else
        {
          Ptr<Packet> cleanP = packet->Copy ();
          YoungdsrRoutingHeader youngdsrRoutingHeader;
          youngdsrRoutingHeader.SetNextHeader (protocol);
          youngdsrRoutingHeader.SetMessageType (2);
          youngdsrRoutingHeader.SetSourceId (GetIDfromIP (source));
          youngdsrRoutingHeader.SetDestId (GetIDfromIP (destination));

          YoungdsrOptionSRHeader sourceRoute;
          std::vector<Ipv4Address> nodeList = toDst.GetVector ();       // Get the route from the route entry we found
          Ipv4Address nextHop = SearchNextHop (m_mainAddress, nodeList);        // Get the next hop address for the route
          if (nextHop == "0.0.0.0")
            {
              PacketNewRoute (cleanP, source, destination, protocol);
              return;
            }
          uint8_t salvage = 0;
          sourceRoute.SetNodesAddress (nodeList);       // Save the whole route in the source route header of the packet
          /// When found a route and use it, UseExtends to the link cache
          if (m_routeCache->IsLinkCache ())
            {
              m_routeCache->UseExtends (nodeList);
            }
          sourceRoute.SetSegmentsLeft ((nodeList.size () - 2));       // The segmentsLeft field will indicate the hops to go
          sourceRoute.SetSalvage (salvage);

          uint8_t length = sourceRoute.GetLength ();

          youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 2);
          youngdsrRoutingHeader.AddYoungdsrOption (sourceRoute);
          cleanP->AddHeader (youngdsrRoutingHeader);

          Ptr<const Packet> mtP = cleanP->Copy ();
          NS_LOG_DEBUG ("maintain packet size " << cleanP->GetSize ());
          // Put the data packet in the maintenance queue for data packet retransmission
          YoungdsrMaintainBuffEntry newEntry (/*Packet=*/ mtP, /*ourAddress=*/ m_mainAddress, /*nextHop=*/ nextHop,
                                                  /*source=*/ source, /*destination=*/ destination, /*ackId=*/ 0,
                                                  /*SegsLeft=*/ nodeList.size () - 2, /*expire time=*/ m_maxMaintainTime);
          bool result = m_maintainBuffer.Enqueue (newEntry);       // Enqueue the packet the the maintenance buffer
          if (result)
            {
              NetworkKey networkKey;
              networkKey.m_ackId = newEntry.GetAckId ();
              networkKey.m_ourAdd = newEntry.GetOurAdd ();
              networkKey.m_nextHop = newEntry.GetNextHop ();
              networkKey.m_source = newEntry.GetSrc ();
              networkKey.m_destination = newEntry.GetDst ();

              PassiveKey passiveKey;
              passiveKey.m_ackId = 0;
              passiveKey.m_source = newEntry.GetSrc ();
              passiveKey.m_destination = newEntry.GetDst ();
              passiveKey.m_segsLeft = newEntry.GetSegsLeft ();

              LinkKey linkKey;
              linkKey.m_source = newEntry.GetSrc ();
              linkKey.m_destination = newEntry.GetDst ();
              linkKey.m_ourAdd = newEntry.GetOurAdd ();
              linkKey.m_nextHop = newEntry.GetNextHop ();

              m_addressForwardCnt[networkKey] = 0;
              m_passiveCnt[passiveKey] = 0;
              m_linkCnt[linkKey] = 0;

              if (m_linkAck)
                {
                  ScheduleLinkPacketRetry (newEntry, protocol);
                }
              else
                {
                  NS_LOG_LOGIC ("Not using link acknowledgment");
                  if (nextHop != destination)
                    {
                      SchedulePassivePacketRetry (newEntry, protocol);
                    }
                  else
                    {
                      // This is the first network retry
                      ScheduleNetworkPacketRetry (newEntry, true, protocol);
                    }
                }
            }

          if (m_sendBuffer.GetSize () != 0 && m_sendBuffer.Find (destination))
            {
              // Try to send packet from *previously* queued entries from send buffer if any
              Simulator::Schedule (MilliSeconds (m_uniformRandomVariable->GetInteger (0,100)),
                                   &YoungdsrRouting::SendPacketFromBuffer, this, sourceRoute, nextHop, protocol);
            }
        }
    }
}

uint16_t
YoungdsrRouting::AddAckReqHeader (Ptr<Packet>& packet, Ipv4Address nextHop)
{
  NS_LOG_FUNCTION (this << packet << nextHop);
  // This packet is used to peek option type
  Ptr<Packet> youngdsrP = packet->Copy ();
  Ptr<Packet> tmpP = packet->Copy ();

  YoungdsrRoutingHeader youngdsrRoutingHeader;
  youngdsrP->RemoveHeader (youngdsrRoutingHeader);          // Remove the DSR header in whole
  uint8_t protocol = youngdsrRoutingHeader.GetNextHeader ();
  uint32_t sourceId = youngdsrRoutingHeader.GetSourceId ();
  uint32_t destinationId = youngdsrRoutingHeader.GetDestId ();
  uint32_t offset = youngdsrRoutingHeader.GetYoungdsrOptionsOffset ();
  tmpP->RemoveAtStart (offset);       // Here the processed size is 8 bytes, which is the fixed sized extension header

  // Get the number of routers' address field
  uint8_t buf[2];
  tmpP->CopyData (buf, sizeof(buf));
  uint8_t numberAddress = (buf[1] - 2) / 4;
//  outputfile2 <<" numberaddress "<< numberAddress <<  "\n" ;

  YoungdsrOptionSRHeader sourceRoute;
  sourceRoute.SetNumberAddress (numberAddress);
  tmpP->RemoveHeader (sourceRoute);               // this is a clean packet without any youngdsr involved headers

  YoungdsrOptionAckReqHeader ackReq;
  m_ackId = m_routeCache->CheckUniqueAckId (nextHop);
  ackReq.SetAckId (m_ackId);
  uint8_t length = (sourceRoute.GetLength () + ackReq.GetLength ());
  YoungdsrRoutingHeader newYoungdsrRoutingHeader;
  newYoungdsrRoutingHeader.SetNextHeader (protocol);
  newYoungdsrRoutingHeader.SetMessageType (2);
  newYoungdsrRoutingHeader.SetSourceId (sourceId);
  newYoungdsrRoutingHeader.SetDestId (destinationId);
  newYoungdsrRoutingHeader.SetPayloadLength (length + 4);
  newYoungdsrRoutingHeader.AddYoungdsrOption (sourceRoute);
  newYoungdsrRoutingHeader.AddYoungdsrOption (ackReq);
  youngdsrP->AddHeader (newYoungdsrRoutingHeader);
  // give the youngdsrP value to packet and then return
  packet = youngdsrP;
  return m_ackId;
}

void
YoungdsrRouting::SendPacket (Ptr<Packet> packet, Ipv4Address source, Ipv4Address nextHop, uint8_t protocol)
{
  Sendpacketcounter = Sendpacketcounter + 1;

//  printf("Sendpacketcounter = %d\n",Sendpacketcounter );
  NS_LOG_FUNCTION (this << packet << source << nextHop << (uint32_t)protocol);
  // Send out the data packet
  m_ipv4Route = SetRoute (nextHop, m_mainAddress);
  Ptr<NetDevice> dev = m_ip->GetNetDevice (m_ip->GetInterfaceForAddress (m_mainAddress));
  m_ipv4Route->SetOutputDevice (dev);

  uint32_t priority = GetPriority (DSR_DATA_PACKET);
  std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator i = m_priorityQueue.find (priority);
  Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = i->second;
  NS_LOG_INFO ("Will be inserting into priority queue number: " << priority);

  //m_downTarget (packet, source, nextHop, GetProtocolNumber (), m_ipv4Route);

  /// \todo New YoungdsrNetworkQueueEntry
  YoungdsrNetworkQueueEntry newEntry (packet, source, nextHop, Simulator::Now (), m_ipv4Route);

  if (youngdsrNetworkQueue->Enqueue (newEntry))
    {
      Scheduler (priority);
    }
  else
    {
      NS_LOG_INFO ("Packet dropped as youngdsr network queue is full");
    }
}

void
YoungdsrRouting::Scheduler (uint32_t priority)
{
  NS_LOG_FUNCTION (this);
  PriorityScheduler (priority, true);
}

void
YoungdsrRouting::PriorityScheduler (uint32_t priority, bool continueWithFirst)
{
  NS_LOG_FUNCTION (this << priority << continueWithFirst);
  uint32_t numPriorities;
  if (continueWithFirst)
    {
      numPriorities = 0;
    }
  else
    {
      numPriorities = priority;
    }
  // priorities ranging from 0 to m_numPriorityQueues, with 0 as the highest priority
  for (uint32_t i = priority; numPriorities < m_numPriorityQueues; numPriorities++)
    {
      std::map<uint32_t, Ptr<YoungdsrNetworkQueue> >::iterator q = m_priorityQueue.find (i);
      Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = q->second;
      uint32_t queueSize = youngdsrNetworkQueue->GetSize ();
      if (queueSize == 0)
        {
          if ((i == (m_numPriorityQueues - 1)) && continueWithFirst)
            {
              i = 0;
            }
          else
            {
              i++;
            }
        }
      else
        {
          uint32_t totalQueueSize = 0;
          for (std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator j = m_priorityQueue.begin (); j != m_priorityQueue.end (); j++)
            {
              NS_LOG_INFO ("The size of the network queue for " << j->first << " is " << j->second->GetSize ());
              totalQueueSize += j->second->GetSize ();
              NS_LOG_INFO ("The total network queue size is " << totalQueueSize);
            }
          if (totalQueueSize > 5)
            {
              // ここでは、キューサイズが5より大きいため、ネットワークキュー内の各パケットの再送信タイマーを増やす必要があります。
              IncreaseRetransTimer ();
            }
          YoungdsrNetworkQueueEntry newEntry;
          youngdsrNetworkQueue->Dequeue (newEntry);
          if (SendRealDown (newEntry))
            {
              NS_LOG_LOGIC ("Packet sent by Youngdsr. Calling PriorityScheduler after some time");
              // packet was successfully sent down. call scheduler after some time
              Simulator::Schedule (MicroSeconds (m_uniformRandomVariable->GetInteger (0, 1000)),
                                   &YoungdsrRouting::PriorityScheduler,this, i, false);
            }
          else
            {
              // packet was dropped by Youngdsr. Call scheduler immediately so that we can
              // send another packet immediately.
              NS_LOG_LOGIC ("Packet dropped by Youngdsr. Calling PriorityScheduler immediately");
              Simulator::Schedule (Seconds (0), &YoungdsrRouting::PriorityScheduler, this, i, false);
            }

          if ((i == (m_numPriorityQueues - 1)) && continueWithFirst)
            {
              i = 0;
            }
          else
            {
              i++;
            }
        }
    }
}

void
YoungdsrRouting::IncreaseRetransTimer ()
{
  NS_LOG_FUNCTION (this);
  // 最初にキューを取得してから、エントリのベクトルをここに保存してから見つける必要がある場合があります
  uint32_t priority = GetPriority (DSR_DATA_PACKET);
  std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator i = m_priorityQueue.find (priority);
  Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = i->second;

  std::vector<YoungdsrNetworkQueueEntry> newNetworkQueue = youngdsrNetworkQueue->GetQueue ();
  for (std::vector<YoungdsrNetworkQueueEntry>::iterator i = newNetworkQueue.begin (); i != newNetworkQueue.end (); i++)
    {
      Ipv4Address nextHop = i->GetNextHopAddress ();
      for (std::map<NetworkKey, Timer>::iterator j = m_addressForwardTimer.begin (); j != m_addressForwardTimer.end (); j++)
        {
          if (nextHop == j->first.m_nextHop)
            {
              NS_LOG_DEBUG ("The network delay left is " << j->second.GetDelayLeft ());
              j->second.SetDelay (j->second.GetDelayLeft () + m_retransIncr);
            }
        }
    }
}

bool
YoungdsrRouting::SendRealDown (YoungdsrNetworkQueueEntry & newEntry)
{
  NS_LOG_FUNCTION (this);
  Ipv4Address source = newEntry.GetSourceAddress ();
  Ipv4Address nextHop = newEntry.GetNextHopAddress ();
  Ptr<Packet> packet = newEntry.GetPacket ()->Copy ();
  Ptr<Ipv4Route> route = newEntry.GetIpv4Route ();
  m_downTarget (packet, source, nextHop, GetProtocolNumber (), route);
  return true;
}

void
YoungdsrRouting::SendPacketFromBuffer (YoungdsrOptionSRHeader const &sourceRoute, Ipv4Address nextHop, uint8_t protocol)
{
  NS_LOG_FUNCTION (this << nextHop << (uint32_t)protocol);
  NS_ASSERT_MSG (!m_downTarget.IsNull (), "Error, YoungdsrRouting cannot send downward");

  // ルートを再構築し、データパケットを再送信します
  std::vector<Ipv4Address> nodeList = sourceRoute.GetNodesAddress ();
  Ipv4Address destination = nodeList.back ();
  Ipv4Address source = nodeList.front ();       // Get the source address
  NS_LOG_INFO ("The nexthop address " << nextHop << " the source " << source << " the destination " << destination);
  /*
   * ここで、送信バッファからデータパケットを見つけようとします。この宛先のパケットが見つかった場合は、送信します
   */
  if (m_sendBuffer.Find (destination))
    {
      /*
      if (m_sendBuffer.Find (GetIDfromIP(malicious))) {

        std::cout << " message " << '\n';
      }
      */

      NS_LOG_DEBUG ("destination over here " << destination);

      /// ルートを見つけて使用すると、リンクキャッシュへのUseExtends
      if (m_routeCache->IsLinkCache ())
        {
          m_routeCache->UseExtends (nodeList);
        }
      YoungdsrSendBuffEntry entry;
      if (m_sendBuffer.Dequeue (destination, entry))
        {
          Ptr<Packet> packet = entry.GetPacket ()->Copy ();
          Ptr<Packet> p = packet->Copy ();      // get a copy of the packet
          // Set the source route option
          YoungdsrRoutingHeader youngdsrRoutingHeader;
          youngdsrRoutingHeader.SetNextHeader (protocol);
          youngdsrRoutingHeader.SetMessageType (2);
          youngdsrRoutingHeader.SetSourceId (GetIDfromIP (source));
          youngdsrRoutingHeader.SetDestId (GetIDfromIP (destination));

          uint8_t length = sourceRoute.GetLength ();
          youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 2);
          youngdsrRoutingHeader.AddYoungdsrOption (sourceRoute);

          p->AddHeader (youngdsrRoutingHeader);

          Ptr<const Packet> mtP = p->Copy ();
          // データパケットの再送信のために、データパケットをメンテナンスキューに入れる
          YoungdsrMaintainBuffEntry newEntry (/*Packet=*/ mtP, /*ourAddress=*/ m_mainAddress, /*nextHop=*/ nextHop,
                                      /*source=*/ source, /*destination=*/ destination, /*ackId=*/ 0,
                                      /*SegsLeft=*/ nodeList.size () - 2, /*expire time=*/ m_maxMaintainTime);
          bool result = m_maintainBuffer.Enqueue (newEntry);       // パケットをメンテナンスバッファに入れます

          if (result)
            {
              NetworkKey networkKey;
              networkKey.m_ackId = newEntry.GetAckId ();
              networkKey.m_ourAdd = newEntry.GetOurAdd ();
              networkKey.m_nextHop = newEntry.GetNextHop ();
              networkKey.m_source = newEntry.GetSrc ();
              networkKey.m_destination = newEntry.GetDst ();

              PassiveKey passiveKey;
              passiveKey.m_ackId = 0;
              passiveKey.m_source = newEntry.GetSrc ();
              passiveKey.m_destination = newEntry.GetDst ();
              passiveKey.m_segsLeft = newEntry.GetSegsLeft ();

              LinkKey linkKey;
              linkKey.m_source = newEntry.GetSrc ();
              linkKey.m_destination = newEntry.GetDst ();
              linkKey.m_ourAdd = newEntry.GetOurAdd ();
              linkKey.m_nextHop = newEntry.GetNextHop ();

              m_addressForwardCnt[networkKey] = 0;
              m_passiveCnt[passiveKey] = 0;
              m_linkCnt[linkKey] = 0;

              if (m_linkAck)
                {
                  ScheduleLinkPacketRetry (newEntry, protocol);
                }
              else
                {
                  NS_LOG_LOGIC ("Not using link acknowledgment");
                  if (nextHop != destination)
                    {
                      SchedulePassivePacketRetry (newEntry, protocol);
                    }
                  else
                    {
                      // This is the first network retry
                      ScheduleNetworkPacketRetry (newEntry, true, protocol);
                    }
                }
            }

          NS_LOG_DEBUG ("send buffer size here and the destination " << m_sendBuffer.GetSize () << " " << destination);
          if (m_sendBuffer.GetSize () != 0 && m_sendBuffer.Find (destination))
            {
              NS_LOG_LOGIC ("Schedule sending the next packet in send buffer");
              Simulator::Schedule (MilliSeconds (m_uniformRandomVariable->GetInteger (0,100)),
                                   &YoungdsrRouting::SendPacketFromBuffer, this, sourceRoute, nextHop, protocol);
            }
        }
      else
        {
          NS_LOG_LOGIC ("All queued packets are out-dated for the destination in send buffer");
        }
    }
  /*
   * ここで、送信バッファからデータパケットを見つけようとします。この宛先のパケットが見つかった場合は、送信します
   */
  else if (m_errorBuffer.Find (destination))
    {
      YoungdsrErrorBuffEntry entry;
      if (m_errorBuffer.Dequeue (destination, entry))
        {
          Ptr<Packet> packet = entry.GetPacket ()->Copy ();
          NS_LOG_DEBUG ("The queued packet size " << packet->GetSize ());

          YoungdsrRoutingHeader youngdsrRoutingHeader;
          Ptr<Packet> copyP = packet->Copy ();
          Ptr<Packet> youngdsrPacket = packet->Copy ();
          youngdsrPacket->RemoveHeader (youngdsrRoutingHeader);
          uint32_t offset = youngdsrRoutingHeader.GetYoungdsrOptionsOffset ();
          copyP->RemoveAtStart (offset);       // ここで処理されるサイズは8バイトで、これは固定サイズの拡張ヘッダーです
          /*
           * データをピークして、オプションタイプと長さおよびセグメントの左フィールドを取得します。
           */
          uint32_t size = copyP->GetSize ();
          uint8_t *data = new uint8_t[size];
          copyP->CopyData (data, size);

          uint8_t optionType = 0;
          optionType = *(data);
          NS_LOG_DEBUG ("The option type value in send packet " << (uint32_t)optionType);
          if (optionType == 3)
            {
              NS_LOG_DEBUG ("The packet is error packet");
              Ptr<youngdsr::YoungdsrOptions> youngdsrOption;
              YoungdsrOptionHeader youngdsrOptionHeader;

              uint8_t errorType = *(data + 2);
              NS_LOG_DEBUG ("The error type");
              if (errorType == 1)
                {
                  NS_LOG_DEBUG ("The packet is route error unreach packet");
                  YoungdsrOptionRerrUnreachHeader rerr;
                  copyP->RemoveHeader (rerr);
                  NS_ASSERT (copyP->GetSize () == 0);
                  uint8_t length = (sourceRoute.GetLength () + rerr.GetLength ());

                  YoungdsrOptionRerrUnreachHeader newUnreach;
                  newUnreach.SetErrorType (1);
                  newUnreach.SetErrorSrc (rerr.GetErrorSrc ());
                  newUnreach.SetUnreachNode (rerr.GetUnreachNode ());
                  newUnreach.SetErrorDst (rerr.GetErrorDst ());
                  newUnreach.SetOriginalDst (rerr.GetOriginalDst ());
                  newUnreach.SetSalvage (rerr.GetSalvage ());       // パケットを回収するかどうかについての値を設定します

                  std::vector<Ipv4Address> nodeList = sourceRoute.GetNodesAddress ();
                  YoungdsrRoutingHeader newRoutingHeader;
                  newRoutingHeader.SetNextHeader (protocol);
                  newRoutingHeader.SetMessageType (1);
                  newRoutingHeader.SetSourceId (GetIDfromIP (rerr.GetErrorSrc ()));
                  newRoutingHeader.SetDestId (GetIDfromIP (rerr.GetErrorDst ()));
                  newRoutingHeader.SetPayloadLength (uint16_t (length) + 4);
                  newRoutingHeader.AddYoungdsrOption (newUnreach);
                  newRoutingHeader.AddYoungdsrOption (sourceRoute);
                  /// ルートを見つけて使用すると、リンクキャッシュへのUseExtends
                  if (m_routeCache->IsLinkCache ())
                    {
                      m_routeCache->UseExtends (nodeList);
                    }
                  SetRoute (nextHop, m_mainAddress);
                  Ptr<Packet> newPacket = Create<Packet> ();
                  newPacket->AddHeader (newRoutingHeader);       // rerrとsourceRouteが付加された拡張ヘッダーを追加します
                  Ptr<NetDevice> dev = m_ip->GetNetDevice (m_ip->GetInterfaceForAddress (m_mainAddress));
                  m_ipv4Route->SetOutputDevice (dev);

                  uint32_t priority = GetPriority (DSR_CONTROL_PACKET);
                  std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator i = m_priorityQueue.find (priority);
                  Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = i->second;
                  NS_LOG_DEBUG ("Will be inserting into priority queue " << youngdsrNetworkQueue << " number: " << priority);

                  //m_downTarget (newPacket, m_mainAddress, nextHop, GetProtocolNumber (), m_ipv4Route);

                  /// \todo New YoungdsrNetworkQueueEntry
                  YoungdsrNetworkQueueEntry newEntry (newPacket, m_mainAddress, nextHop, Simulator::Now (), m_ipv4Route);

                  if (youngdsrNetworkQueue->Enqueue (newEntry))
                    {
                      Scheduler (priority);
                    }
                  else
                    {
                      NS_LOG_INFO ("Packet dropped as youngdsr network queue is full");
                    }
                }
            }

          if (m_errorBuffer.GetSize () != 0 && m_errorBuffer.Find (destination))
            {
              NS_LOG_LOGIC ("Schedule sending the next packet in error buffer");
              Simulator::Schedule (MilliSeconds (m_uniformRandomVariable->GetInteger (0,100)),
                                   &YoungdsrRouting::SendPacketFromBuffer, this, sourceRoute, nextHop, protocol);
            }
        }
    }
  else
    {
      NS_LOG_DEBUG ("Packet not found in either the send or error buffer");
    }
}

bool
YoungdsrRouting::PassiveEntryCheck (Ptr<Packet> packet, Ipv4Address source, Ipv4Address destination, uint8_t segsLeft,
                               uint16_t fragmentOffset, uint16_t identification, bool saveEntry)
{
  NS_LOG_FUNCTION (this << packet << source << destination << (uint32_t)segsLeft);

  Ptr<Packet> p = packet->Copy ();
  // ここで、セグメントの左の値は、以前のホップがバッファエントリを維持することを確認するために1を加える必要がある
  YoungdsrPassiveBuffEntry newEntry;
  newEntry.SetPacket (p);
  newEntry.SetSource (source);
  newEntry.SetDestination (destination);
  newEntry.SetIdentification (identification);
  newEntry.SetFragmentOffset (fragmentOffset);
  newEntry.SetSegsLeft (segsLeft);  // 残っているセグメントが1より大きいことを確認しようとします


  NS_LOG_DEBUG ("The passive buffer size " << m_passiveBuffer->GetSize ());

  if (m_passiveBuffer->AllEqual (newEntry) && (!saveEntry))
    {
      // PromiscEqual関数は、等しい値が見つかった場合、メンテナンスバッファエントリを削除します
       //送信元アドレスと宛先アドレス、ackId、およびセグメントの残りの値のみを比較します
      NS_LOG_DEBUG ("We get the all equal for passive buffer here");

      YoungdsrMaintainBuffEntry mbEntry;
      mbEntry.SetPacket (p);
      mbEntry.SetSrc (source);
      mbEntry.SetDst (destination);
      mbEntry.SetAckId (0);
      mbEntry.SetSegsLeft (segsLeft + 1);

      CancelPassivePacketTimer (mbEntry);
      return true;
    }
  if (saveEntry)
    {
      /// Save this passive buffer entry for later check
      m_passiveBuffer->Enqueue (newEntry);
    }
  return false;
}

bool
YoungdsrRouting::CancelPassiveTimer (Ptr<Packet> packet, Ipv4Address source, Ipv4Address destination,
                                uint8_t segsLeft)
{
  NS_LOG_FUNCTION (this << packet << source << destination << (uint32_t)segsLeft);

  NS_LOG_DEBUG ("Cancel the passive timer");

  Ptr<Packet> p = packet->Copy ();
  // ここで、セグメントの左の値は、以前のホップがバッファエントリを維持することを確認するために1を加える必要がある
  YoungdsrMaintainBuffEntry newEntry;
  newEntry.SetPacket (p);
  newEntry.SetSrc (source);
  newEntry.SetDst (destination);
  newEntry.SetAckId (0);
  newEntry.SetSegsLeft (segsLeft + 1);

  if (m_maintainBuffer.PromiscEqual (newEntry))
    {
      // PromiscEqual関数は、等しい値が見つかった場合、メンテナンスバッファエントリを削除します
       //送信元アドレスと宛先アドレス、ackId、およびセグメントの残りの値のみを比較します
      CancelPassivePacketTimer (newEntry);
      return true;
    }
  return false;
}

void
YoungdsrRouting::CallCancelPacketTimer (uint16_t ackId, Ipv4Header const& ipv4Header, Ipv4Address realSrc, Ipv4Address realDst)
{
  NS_LOG_FUNCTION (this << (uint32_t)ackId << ipv4Header << realSrc << realDst);
  Ipv4Address sender = ipv4Header.GetDestination ();
  Ipv4Address receiver = ipv4Header.GetSource ();
  /*
   * メンテナンスエントリを比較するために使用されない、メンテナンスバッファを満たすパケットを作成します。
    *理由は、ackヘッダーに元のパケットコピーがない
   */
  Ptr<Packet> mainP = Create<Packet> ();
  YoungdsrMaintainBuffEntry newEntry (/*Packet=*/ mainP, /*ourAddress=*/ sender, /*nextHop=*/ receiver,
                                          /*source=*/ realSrc, /*destination=*/ realDst, /*ackId=*/ ackId,
                                          /*SegsLeft=*/ 0, /*expire time=*/ Simulator::Now ());
  CancelNetworkPacketTimer (newEntry);  // Only need to cancel network packet timer
}

void
YoungdsrRouting::CancelPacketAllTimer (YoungdsrMaintainBuffEntry & mb)
{
  NS_LOG_FUNCTION (this);
  CancelLinkPacketTimer (mb);
  CancelNetworkPacketTimer (mb);
  CancelPassivePacketTimer (mb);
}

void
YoungdsrRouting::CancelLinkPacketTimer (YoungdsrMaintainBuffEntry & mb)
{
  NS_LOG_FUNCTION (this);
  LinkKey linkKey;
  linkKey.m_ourAdd = mb.GetOurAdd ();
  linkKey.m_nextHop = mb.GetNextHop ();
  linkKey.m_source = mb.GetSrc ();
  linkKey.m_destination = mb.GetDst ();
  /*
   * Here we have found the entry for send retries, so we get the value and increase it by one
   */
  /// TODO need to think about this part
  m_linkCnt[linkKey] = 0;
  m_linkCnt.erase (linkKey);

  // TODO if find the linkkey, we need to remove it

  // Find the network acknowledgment timer
  std::map<LinkKey, Timer>::const_iterator i =
    m_linkAckTimer.find (linkKey);
  if (i == m_linkAckTimer.end ())
    {
      NS_LOG_INFO ("did not find the link timer");
    }
  else
    {
      NS_LOG_INFO ("did find the link timer");
      /*
       * Schedule the packet retry
       * Push back the nextHop, source, destination address
       */
      m_linkAckTimer[linkKey].Cancel ();
      m_linkAckTimer[linkKey].Remove ();
      if (m_linkAckTimer[linkKey].IsRunning ())
        {
          NS_LOG_INFO ("Timer not canceled");
        }
      m_linkAckTimer.erase (linkKey);
    }

  // Erase the maintenance entry
  // yet this does not check the segments left value here
  NS_LOG_DEBUG ("The link buffer size " << m_maintainBuffer.GetSize ());
  if (m_maintainBuffer.LinkEqual (mb))
    {
      NS_LOG_INFO ("Link acknowledgment received, remove same maintenance buffer entry");
    }
}

void
YoungdsrRouting::CancelNetworkPacketTimer (YoungdsrMaintainBuffEntry & mb)
{
  NS_LOG_FUNCTION (this);
  NetworkKey networkKey;
  networkKey.m_ackId = mb.GetAckId ();
  networkKey.m_ourAdd = mb.GetOurAdd ();
  networkKey.m_nextHop = mb.GetNextHop ();
  networkKey.m_source = mb.GetSrc ();
  networkKey.m_destination = mb.GetDst ();
  /*
   * Here we have found the entry for send retries, so we get the value and increase it by one
   */
  m_addressForwardCnt[networkKey] = 0;
  m_addressForwardCnt.erase (networkKey);

  NS_LOG_INFO ("ackId " << mb.GetAckId () << " ourAdd " << mb.GetOurAdd () << " nextHop " << mb.GetNextHop ()
                        << " source " << mb.GetSrc () << " destination " << mb.GetDst ()
                        << " segsLeft " << (uint32_t)mb.GetSegsLeft ()
               );
  // Find the network acknowledgment timer
  std::map<NetworkKey, Timer>::const_iterator i =
    m_addressForwardTimer.find (networkKey);
  if (i == m_addressForwardTimer.end ())
    {
      NS_LOG_INFO ("did not find the packet timer");
    }
  else
    {
      NS_LOG_INFO ("did find the packet timer");
      /*
       * Schedule the packet retry
       * Push back the nextHop, source, destination address
       */
      m_addressForwardTimer[networkKey].Cancel ();
      m_addressForwardTimer[networkKey].Remove ();
      if (m_addressForwardTimer[networkKey].IsRunning ())
        {
          NS_LOG_INFO ("Timer not canceled");
        }
      m_addressForwardTimer.erase (networkKey);
    }
  // Erase the maintenance entry
  // yet this does not check the segments left value here
  if (m_maintainBuffer.NetworkEqual (mb))
    {
      NS_LOG_INFO ("Remove same maintenance buffer entry based on network acknowledgment");
    }
}

void
YoungdsrRouting::CancelPassivePacketTimer (YoungdsrMaintainBuffEntry & mb)
{
  NS_LOG_FUNCTION (this);
  PassiveKey passiveKey;
  passiveKey.m_ackId = 0;
  passiveKey.m_source = mb.GetSrc ();
  passiveKey.m_destination = mb.GetDst ();
  passiveKey.m_segsLeft = mb.GetSegsLeft ();

  m_passiveCnt[passiveKey] = 0;
  m_passiveCnt.erase (passiveKey);

  // Find the passive acknowledgment timer
  std::map<PassiveKey, Timer>::const_iterator j =
    m_passiveAckTimer.find (passiveKey);
  if (j == m_passiveAckTimer.end ())
    {
      NS_LOG_INFO ("did not find the passive timer");
    }
  else
    {
      NS_LOG_INFO ("find the passive timer");
      /*
       * Cancel passive acknowledgment timer
       */
      m_passiveAckTimer[passiveKey].Cancel ();
      m_passiveAckTimer[passiveKey].Remove ();
      if (m_passiveAckTimer[passiveKey].IsRunning ())
        {
          NS_LOG_INFO ("Timer not canceled");
        }
      m_passiveAckTimer.erase (passiveKey);
    }
}

void
YoungdsrRouting::CancelPacketTimerNextHop (Ipv4Address nextHop, uint8_t protocol)
{
  NS_LOG_FUNCTION (this << nextHop << (uint32_t)protocol);

  YoungdsrMaintainBuffEntry entry;
  std::vector<Ipv4Address> previousErrorDst;
  if (m_maintainBuffer.Dequeue (nextHop, entry))
    {
      Ipv4Address source = entry.GetSrc ();
      Ipv4Address destination = entry.GetDst ();

      Ptr<Packet> youngdsrP = entry.GetPacket ()->Copy ();
      Ptr<Packet> p = youngdsrP->Copy ();
      Ptr<Packet> packet = youngdsrP->Copy ();
      YoungdsrRoutingHeader youngdsrRoutingHeader;
      youngdsrP->RemoveHeader (youngdsrRoutingHeader);          // Remove the youngdsr header in whole
      uint32_t offset = youngdsrRoutingHeader.GetYoungdsrOptionsOffset ();
      p->RemoveAtStart (offset);

      // Get the number of routers' address field
      uint8_t buf[2];
      p->CopyData (buf, sizeof(buf));
      uint8_t numberAddress = (buf[1] - 2) / 4;
      NS_LOG_DEBUG ("The number of addresses " << (uint32_t)numberAddress);
      YoungdsrOptionSRHeader sourceRoute;
      sourceRoute.SetNumberAddress (numberAddress);
      p->RemoveHeader (sourceRoute);
      std::vector<Ipv4Address> nodeList = sourceRoute.GetNodesAddress ();
      uint8_t salvage = sourceRoute.GetSalvage ();
      Ipv4Address address1 = nodeList[1];
      PrintVector (nodeList);

      /*
       * サルベージが0でない場合、ルートの最初のアドレスをエラーヘッダーのエラーdstとして使用します
        *それ以外の場合、パケットのソースをエラー宛先として使用します
       */
      Ipv4Address errorDst;
      if (salvage)
        {
          errorDst = address1;
        }
      else
        {
          errorDst = source;
        }
      /// TODO if the errorDst is not seen before
      if (std::find (previousErrorDst.begin (), previousErrorDst.end (), destination) == previousErrorDst.end ())
        {
          NS_LOG_DEBUG ("have not seen this dst before " << errorDst << " in " << previousErrorDst.size ());
          SendUnreachError (nextHop, errorDst, destination, salvage, protocol);
          previousErrorDst.push_back (errorDst);
        }

      /*
       * パケットタイマーをキャンセルしてから、データパケットを回収します
       */

      CancelPacketAllTimer (entry);
      SalvagePacket (packet, source, destination, protocol);

      if (m_maintainBuffer.GetSize () && m_maintainBuffer.Find (nextHop))
        {
          NS_LOG_INFO ("Cancel the packet timer for next maintenance entry");
          Simulator::Schedule (MilliSeconds (m_uniformRandomVariable->GetInteger (0,100)),
                               &YoungdsrRouting::CancelPacketTimerNextHop,this,nextHop,protocol);
        }
    }
  else
    {
      NS_LOG_INFO ("Maintenance buffer entry not found");
    }
  /// TODO need to think about whether we need the network queue entry or not
}

void
YoungdsrRouting::SalvagePacket (Ptr<const Packet> packet, Ipv4Address source, Ipv4Address dst, uint8_t protocol)
{
  NS_LOG_FUNCTION (this << packet << source << dst << (uint32_t)protocol);
  // Create two copies of packet
  Ptr<Packet> p = packet->Copy ();
  Ptr<Packet> newPacket = packet->Copy ();
  // Remove the routing header in a whole to get a clean packet
  YoungdsrRoutingHeader youngdsrRoutingHeader;
  p->RemoveHeader (youngdsrRoutingHeader);
  // Remove offset of youngdsr routing header
  uint8_t offset = youngdsrRoutingHeader.GetYoungdsrOptionsOffset ();
  newPacket->RemoveAtStart (offset);

  // Get the number of routers' address field
  uint8_t buf[2];
  newPacket->CopyData (buf, sizeof(buf));
  uint8_t numberAddress = (buf[1] - 2) / 4;

  YoungdsrOptionSRHeader sourceRoute;
  sourceRoute.SetNumberAddress (numberAddress);
  newPacket->RemoveHeader (sourceRoute);
  uint8_t salvage = sourceRoute.GetSalvage ();
  /*
   * この先のために他のルートのためのルートキャッシュで見て
   */
  YoungdsrRouteCacheEntry toDst;
  bool findRoute = m_routeCache->LookupRoute (dst, toDst);
  if (findRoute && (salvage < m_maxSalvageCount))
    {
      NS_LOG_DEBUG ("We have found a route for the packet");
      YoungdsrRoutingHeader newYoungdsrRoutingHeader;
      newYoungdsrRoutingHeader.SetNextHeader (protocol);
      newYoungdsrRoutingHeader.SetMessageType (2);
      newYoungdsrRoutingHeader.SetSourceId (GetIDfromIP (source));
      newYoungdsrRoutingHeader.SetDestId (GetIDfromIP (dst));

      std::vector<Ipv4Address> nodeList = toDst.GetVector ();     // Get the route from the route entry we found
      Ipv4Address nextHop = SearchNextHop (m_mainAddress, nodeList);      // Get the next hop address for the route
      if (nextHop == "0.0.0.0")
        {
          PacketNewRoute (p, source, dst, protocol);
          return;
        }
      // Increase the salvage count by 1
      salvage++;
      YoungdsrOptionSRHeader sourceRoute;
      sourceRoute.SetSalvage (salvage);
      sourceRoute.SetNodesAddress (nodeList);     // パケットのソースルートヘッダーにルート全体を保存します
      sourceRoute.SetSegmentsLeft ((nodeList.size () - 2));     // segmentLeftフィールドは、移動するホップを示します
      /// ルートを見つけて使用すると、リンクキャッシュへのUseExtends
      if (m_routeCache->IsLinkCache ())
        {
          m_routeCache->UseExtends (nodeList);
        }
      uint8_t length = sourceRoute.GetLength ();
      NS_LOG_INFO ("length of source route header " << (uint32_t)(sourceRoute.GetLength ()));
      newYoungdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 2);
      newYoungdsrRoutingHeader.AddYoungdsrOption (sourceRoute);
      p->AddHeader (newYoungdsrRoutingHeader);

      SetRoute (nextHop, m_mainAddress);
      Ptr<NetDevice> dev = m_ip->GetNetDevice (m_ip->GetInterfaceForAddress (m_mainAddress));
      m_ipv4Route->SetOutputDevice (dev);

      // データパケットを送信する
      uint32_t priority = GetPriority (DSR_DATA_PACKET);
      std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator i = m_priorityQueue.find (priority);
      Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = i->second;
      NS_LOG_DEBUG ("Will be inserting into priority queue " << youngdsrNetworkQueue << " number: " << priority);

      //m_downTarget (p, m_mainAddress, nextHop, GetProtocolNumber (), m_ipv4Route);

      /// \todo New YoungdsrNetworkQueueEntry
      YoungdsrNetworkQueueEntry newEntry (p, m_mainAddress, nextHop, Simulator::Now (), m_ipv4Route);

      if (youngdsrNetworkQueue->Enqueue (newEntry))
        {
          Scheduler (priority);
        }
      else
        {
          NS_LOG_INFO ("Packet dropped as youngdsr network queue is full");
        }

      /*
       * Mark the next hop address in blacklist
       */
//      NS_LOG_DEBUG ("Save the next hop node in blacklist");
//      m_rreqTable->MarkLinkAsUnidirectional (nextHop, m_blacklistTimeout);
    }
  else
    {
      NS_LOG_DEBUG ("Will not salvage this packet, silently drop");
    }
}

void
YoungdsrRouting::ScheduleLinkPacketRetry (YoungdsrMaintainBuffEntry & mb,
                                     uint8_t protocol)
{
  NS_LOG_FUNCTION (this << (uint32_t) protocol);

  Ptr<Packet> p = mb.GetPacket ()->Copy ();
  Ipv4Address source = mb.GetSrc ();
  Ipv4Address nextHop = mb.GetNextHop ();

  // Send the data packet out before schedule the next packet transmission
  SendPacket (p, source, nextHop, protocol);

  LinkKey linkKey;
  linkKey.m_source = mb.GetSrc ();
  linkKey.m_destination = mb.GetDst ();
  linkKey.m_ourAdd = mb.GetOurAdd ();
  linkKey.m_nextHop = mb.GetNextHop ();

  if (m_linkAckTimer.find (linkKey) == m_linkAckTimer.end ())
    {
      Timer timer (Timer::CANCEL_ON_DESTROY);
      m_linkAckTimer[linkKey] = timer;
    }
  m_linkAckTimer[linkKey].SetFunction (&YoungdsrRouting::LinkScheduleTimerExpire, this);
  m_linkAckTimer[linkKey].Remove ();
  m_linkAckTimer[linkKey].SetArguments (mb, protocol);
  m_linkAckTimer[linkKey].Schedule (m_linkAckTimeout);
}

void
YoungdsrRouting::SchedulePassivePacketRetry (YoungdsrMaintainBuffEntry & mb,
                                        uint8_t protocol)
{
  NS_LOG_FUNCTION (this << (uint32_t)protocol);

  Ptr<Packet> p = mb.GetPacket ()->Copy ();
  Ipv4Address source = mb.GetSrc ();
  Ipv4Address nextHop = mb.GetNextHop ();

  // Send the data packet out before schedule the next packet transmission
  SendPacket (p, source, nextHop, protocol);

  PassiveKey passiveKey;
  passiveKey.m_ackId = 0;
  passiveKey.m_source = mb.GetSrc ();
  passiveKey.m_destination = mb.GetDst ();
  passiveKey.m_segsLeft = mb.GetSegsLeft ();

  if (m_passiveAckTimer.find (passiveKey) == m_passiveAckTimer.end ())
    {
      Timer timer (Timer::CANCEL_ON_DESTROY);
      m_passiveAckTimer[passiveKey] = timer;
    }
  NS_LOG_DEBUG ("The passive acknowledgment option for data packet");
  m_passiveAckTimer[passiveKey].SetFunction (&YoungdsrRouting::PassiveScheduleTimerExpire, this);
  m_passiveAckTimer[passiveKey].Remove ();
  m_passiveAckTimer[passiveKey].SetArguments (mb, protocol);
  m_passiveAckTimer[passiveKey].Schedule (m_passiveAckTimeout);
}

void
YoungdsrRouting::ScheduleNetworkPacketRetry (YoungdsrMaintainBuffEntry & mb,
                                        bool isFirst,
                                        uint8_t protocol)
{
  Ptr<Packet> p = Create<Packet> ();
  Ptr<Packet> youngdsrP = Create<Packet> ();
  // The new entry will be used for retransmission
  NetworkKey networkKey;
  Ipv4Address nextHop = mb.GetNextHop ();
  NS_LOG_DEBUG ("is the first retry or not " << isFirst);
  if (isFirst)
    {
      // This is the very first network packet retry
      p = mb.GetPacket ()->Copy ();
      // Here we add the ack request header to the data packet for network acknowledgement
      uint16_t ackId = AddAckReqHeader (p, nextHop);

      Ipv4Address source = mb.GetSrc ();
      Ipv4Address nextHop = mb.GetNextHop ();
      // Send the data packet out before schedule the next packet transmission
      SendPacket (p, source, nextHop, protocol);

      youngdsrP = p->Copy ();
      YoungdsrMaintainBuffEntry newEntry = mb;
      // The function AllEqual will find the exact entry and delete it if found
      m_maintainBuffer.AllEqual (mb);
      newEntry.SetPacket (youngdsrP);
      newEntry.SetAckId (ackId);
      newEntry.SetExpireTime (m_maxMaintainTime);

      networkKey.m_ackId = newEntry.GetAckId ();
      networkKey.m_ourAdd = newEntry.GetOurAdd ();
      networkKey.m_nextHop = newEntry.GetNextHop ();
      networkKey.m_source = newEntry.GetSrc ();
      networkKey.m_destination = newEntry.GetDst ();

      m_addressForwardCnt[networkKey] = 0;
      if (!m_maintainBuffer.Enqueue (newEntry))
        {
          NS_LOG_ERROR ("Failed to enqueue packet retry");
        }

      if (m_addressForwardTimer.find (networkKey) == m_addressForwardTimer.end ())
        {
          Timer timer (Timer::CANCEL_ON_DESTROY);
          m_addressForwardTimer[networkKey] = timer;
        }

      // After m_tryPassiveAcks, schedule the packet retransmission using network acknowledgment option
      m_addressForwardTimer[networkKey].SetFunction (&YoungdsrRouting::NetworkScheduleTimerExpire, this);
      m_addressForwardTimer[networkKey].Remove ();
      m_addressForwardTimer[networkKey].SetArguments (newEntry, protocol);
      NS_LOG_DEBUG ("The packet retries time for " << newEntry.GetAckId () << " is " << m_sendRetries
                                                   << " and the delay time is " << Time (2 * m_nodeTraversalTime).GetSeconds ());
      // Back-off mechanism
      m_addressForwardTimer[networkKey].Schedule (Time (2 * m_nodeTraversalTime));
    }
  else
    {
      networkKey.m_ackId = mb.GetAckId ();
      networkKey.m_ourAdd = mb.GetOurAdd ();
      networkKey.m_nextHop = mb.GetNextHop ();
      networkKey.m_source = mb.GetSrc ();
      networkKey.m_destination = mb.GetDst ();
      /*
       *ここで、再試行を送信するためのエントリを見つけたので、値を取得して1ずつ増やします
       */
      m_sendRetries = m_addressForwardCnt[networkKey];
      NS_LOG_DEBUG ("The packet retry we have done " << m_sendRetries);

      p = mb.GetPacket ()->Copy ();
      youngdsrP = mb.GetPacket ()->Copy ();

      Ipv4Address source = mb.GetSrc ();
      Ipv4Address nextHop = mb.GetNextHop ();
      // 次のパケット送信をスケジュールする前にデータパケットを送信します
      SendPacket (p, source, nextHop, protocol);

      NS_LOG_DEBUG ("The packet with youngdsr header " << youngdsrP->GetSize ());
      networkKey.m_ackId = mb.GetAckId ();
      networkKey.m_ourAdd = mb.GetOurAdd ();
      networkKey.m_nextHop = mb.GetNextHop ();
      networkKey.m_source = mb.GetSrc ();
      networkKey.m_destination = mb.GetDst ();
      /*
       *  データパケットがACKを受信せずに最大TTLでSendRetries回試行された場合、対応する宛先宛てのすべてのデータパケットは送信バッファーからドロップされる必要があります（SHOULD）
       *
       * maxMaintRexmtは、パッシブACKパケット用に1を減らす必要もあります
       */
       /*
       *特定のパケットの送信再試行時間が既に最大メンテナンス再送信時間を過ぎているかどうかを確認する
       */

      //m_tryPassiveAcksの後、ネットワーク確認オプションを使用してパケットの再送信をスケジュールします
      m_addressForwardTimer[networkKey].SetFunction (&YoungdsrRouting::NetworkScheduleTimerExpire, this);
      m_addressForwardTimer[networkKey].Remove ();
      m_addressForwardTimer[networkKey].SetArguments (mb, protocol);
      NS_LOG_DEBUG ("The packet retries time for " << mb.GetAckId () << " is " << m_sendRetries
                                                   << " and the delay time is " << Time (2 * m_sendRetries *  m_nodeTraversalTime).GetSeconds ());
      // Back-off mechanism
      m_addressForwardTimer[networkKey].Schedule (Time (2 * m_sendRetries * m_nodeTraversalTime));
    }
}

void
YoungdsrRouting::LinkScheduleTimerExpire  (YoungdsrMaintainBuffEntry & mb,
                                      uint8_t protocol)
{
  NS_LOG_FUNCTION (this << (uint32_t)protocol);
  Ipv4Address nextHop = mb.GetNextHop ();
  Ptr<const Packet> packet = mb.GetPacket ();
  SetRoute (nextHop, m_mainAddress);
  Ptr<Packet> p = packet->Copy ();

  LinkKey lk;
  lk.m_source = mb.GetSrc ();
  lk.m_destination = mb.GetDst ();
  lk.m_ourAdd = mb.GetOurAdd ();
  lk.m_nextHop = mb.GetNextHop ();

  // Cancel passive ack timer
  m_linkAckTimer[lk].Cancel ();
  m_linkAckTimer[lk].Remove ();
  if (m_linkAckTimer[lk].IsRunning ())
    {
      NS_LOG_DEBUG ("Timer not canceled");
    }
  m_linkAckTimer.erase (lk);

  // Increase the send retry times
  m_linkRetries = m_linkCnt[lk];
  if (m_linkRetries < m_tryLinkAcks)
    {
      m_linkCnt[lk] = ++m_linkRetries;
      ScheduleLinkPacketRetry (mb, protocol);
    }
  else
    {
      NS_LOG_INFO ("We need to send error messages now");

      // Delete all the routes including the links
      m_routeCache->DeleteAllRoutesIncludeLink (m_mainAddress, nextHop, m_mainAddress);
      /*
       * ここでは、nextHopとしてネクストホップアドレスを持つすべてのパケットのパケット再送信時間をキャンセルします。
        * nextHopアドレス宛てのすべてのパケットのパケットをサルベージする
        *これは、到達不能エラーをソースに送信する責任もあります
       */
      CancelPacketTimerNextHop (nextHop, protocol);
    }
}

void
YoungdsrRouting::PassiveScheduleTimerExpire  (YoungdsrMaintainBuffEntry & mb,
                                         uint8_t protocol)
{
  NS_LOG_FUNCTION (this << (uint32_t)protocol);
  Ipv4Address nextHop = mb.GetNextHop ();
  Ptr<const Packet> packet = mb.GetPacket ();
  SetRoute (nextHop, m_mainAddress);
  Ptr<Packet> p = packet->Copy ();

  PassiveKey pk;
  pk.m_ackId = 0;
  pk.m_source = mb.GetSrc ();
  pk.m_destination = mb.GetDst ();
  pk.m_segsLeft = mb.GetSegsLeft ();

  // Cancel passive ack timer
  m_passiveAckTimer[pk].Cancel ();
  m_passiveAckTimer[pk].Remove ();
  if (m_passiveAckTimer[pk].IsRunning ())
    {
      NS_LOG_DEBUG ("Timer not canceled");
    }
  m_passiveAckTimer.erase (pk);

  // Increase the send retry times
  m_passiveRetries = m_passiveCnt[pk];
  if (m_passiveRetries < m_tryPassiveAcks)
    {
      m_passiveCnt[pk] = ++m_passiveRetries;
      SchedulePassivePacketRetry (mb, protocol);
    }
  else
    {
      // This is the first network acknowledgement retry
      // Cancel the passive packet timer now and remove maintenance buffer entry for it
      CancelPassivePacketTimer (mb);
      ScheduleNetworkPacketRetry (mb, true, protocol);
    }
}

int64_t
YoungdsrRouting::AssignStreams (int64_t stream)
{
  NS_LOG_FUNCTION (this << stream);
  m_uniformRandomVariable->SetStream (stream);
  return 1;
}

void
YoungdsrRouting::NetworkScheduleTimerExpire  (YoungdsrMaintainBuffEntry & mb,
                                         uint8_t protocol)
{
  Ptr<Packet> p = mb.GetPacket ()->Copy ();
  Ipv4Address source = mb.GetSrc ();
  Ipv4Address nextHop = mb.GetNextHop ();
  Ipv4Address dst = mb.GetDst ();

  NetworkKey networkKey;
  networkKey.m_ackId = mb.GetAckId ();
  networkKey.m_ourAdd = mb.GetOurAdd ();
  networkKey.m_nextHop = nextHop;
  networkKey.m_source = source;
  networkKey.m_destination = dst;

  // Increase the send retry times
  m_sendRetries = m_addressForwardCnt[networkKey];

  if (m_sendRetries >= m_maxMaintRexmt)
    {
      // Delete all the routes including the links
      m_routeCache->DeleteAllRoutesIncludeLink (m_mainAddress, nextHop, m_mainAddress);
      /*
       * ここでは、nextHopとしてネクストホップアドレスを持つすべてのパケットのパケット再送信時間をキャンセルします。
        * nextHopアドレス宛てのすべてのパケットのパケットをサルベージする
       */
      CancelPacketTimerNextHop (nextHop, protocol);
    }
  else
    {
      m_addressForwardCnt[networkKey] = ++m_sendRetries;
      ScheduleNetworkPacketRetry (mb, false, protocol);
    }
}

void
YoungdsrRouting::ForwardPacket (Ptr<const Packet> packet,
                           YoungdsrOptionSRHeader &sourceRoute,
                           Ipv4Header const& ipv4Header,
                           Ipv4Address source,
                           Ipv4Address nextHop,
                           Ipv4Address targetAddress,
                           uint8_t protocol,
                           Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this << packet << sourceRoute << source << nextHop << targetAddress << (uint32_t)protocol << route);
  NS_ASSERT_MSG (!m_downTarget.IsNull (), "Error, YoungdsrRouting cannot send downward");

  YoungdsrRoutingHeader youngdsrRoutingHeader;
  youngdsrRoutingHeader.SetNextHeader (protocol);
  youngdsrRoutingHeader.SetMessageType (2);
  youngdsrRoutingHeader.SetSourceId (GetIDfromIP (source));
  youngdsrRoutingHeader.SetDestId (GetIDfromIP (targetAddress));

  // We get the salvage value in sourceRoute header and set it to route error header if triggered error
  Ptr<Packet> p = packet->Copy ();
  uint8_t length = sourceRoute.GetLength ();
  youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 2);
  youngdsrRoutingHeader.AddYoungdsrOption (sourceRoute);
  p->AddHeader (youngdsrRoutingHeader);

  Ptr<const Packet> mtP = p->Copy ();

  YoungdsrMaintainBuffEntry newEntry (/*Packet=*/ mtP, /*ourAddress=*/ m_mainAddress, /*nextHop=*/ nextHop,
                              /*source=*/ source, /*destination=*/ targetAddress, /*ackId=*/ m_ackId,
                              /*SegsLeft=*/ sourceRoute.GetSegmentsLeft (), /*expire time=*/ m_maxMaintainTime);
  bool result = m_maintainBuffer.Enqueue (newEntry);

  if (result)
    {
      NetworkKey networkKey;
      networkKey.m_ackId = newEntry.GetAckId ();
      networkKey.m_ourAdd = newEntry.GetOurAdd ();
      networkKey.m_nextHop = newEntry.GetNextHop ();
      networkKey.m_source = newEntry.GetSrc ();
      networkKey.m_destination = newEntry.GetDst ();

      PassiveKey passiveKey;
      passiveKey.m_ackId = 0;
      passiveKey.m_source = newEntry.GetSrc ();
      passiveKey.m_destination = newEntry.GetDst ();
      passiveKey.m_segsLeft = newEntry.GetSegsLeft ();

      LinkKey linkKey;
      linkKey.m_source = newEntry.GetSrc ();
      linkKey.m_destination = newEntry.GetDst ();
      linkKey.m_ourAdd = newEntry.GetOurAdd ();
      linkKey.m_nextHop = newEntry.GetNextHop ();

      m_addressForwardCnt[networkKey] = 0;
      m_passiveCnt[passiveKey] = 0;
      m_linkCnt[linkKey] = 0;

      if (m_linkAck)
        {
          ScheduleLinkPacketRetry (newEntry, protocol);
        }
      else
        {
          NS_LOG_LOGIC ("Not using link acknowledgment");
          if (nextHop != targetAddress)
            {
              SchedulePassivePacketRetry (newEntry, protocol);
            }
          else
            {
              // This is the first network retry
              ScheduleNetworkPacketRetry (newEntry, true, protocol);
            }
        }
    }
}

void
YoungdsrRouting::SendInitialRequest (Ipv4Address source,
                                Ipv4Address destination,
                                uint8_t protocol)
{
  NS_LOG_FUNCTION (this << source << destination << (uint32_t)protocol);
  NS_ASSERT_MSG (!m_downTarget.IsNull (), "Error, YoungdsrRouting cannot send downward");
  Ptr<Packet> packet = Create<Packet> ();
  // Create an empty Ipv4 route ptr
  Ptr<Ipv4Route> route;
  /*
   * Construct the route request option header
   */
  YoungdsrRoutingHeader youngdsrRoutingHeader;
  youngdsrRoutingHeader.SetNextHeader (protocol);
  youngdsrRoutingHeader.SetMessageType (1);
  youngdsrRoutingHeader.SetSourceId (GetIDfromIP (source));
  youngdsrRoutingHeader.SetDestId (255);

  YoungdsrOptionRreqHeader rreqHeader;                                  // has an alignment of 4n+0
  rreqHeader.AddNodeAddress (m_mainAddress);                       // Add our own address in the header
  rreqHeader.SetTarget (destination);
  m_requestId = m_rreqTable->CheckUniqueRreqId (destination);      // Check the Id cache for duplicate ones
  rreqHeader.SetId (m_requestId);

  youngdsrRoutingHeader.AddYoungdsrOption (rreqHeader);                      // Add the rreqHeader to the youngdsr extension header
  uint8_t length = rreqHeader.GetLength ();
  youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 2);
  packet->AddHeader (youngdsrRoutingHeader);

  // Schedule the route requests retry with non-propagation set true
  bool nonProp = true;
  std::vector<Ipv4Address> address;
  address.push_back (source);
  address.push_back (destination);
  /*
   * ソケットip ttlタグをパケットに追加して、ルート要求の範囲を制限します
   */
  SocketIpTtlTag tag;
  tag.SetTtl (0);
  Ptr<Packet> nonPropPacket = packet->Copy ();
  nonPropPacket->AddPacketTag (tag);
  // Increase the request count
  m_rreqTable->FindAndUpdate (destination);
  SendRequest (nonPropPacket, source);
  // Schedule the next route request
  ScheduleRreqRetry (packet, address, nonProp, m_requestId, protocol);
}

void
YoungdsrRouting::SendErrorRequest (YoungdsrOptionRerrUnreachHeader &rerr, uint8_t protocol)
{
  NS_LOG_FUNCTION (this << (uint32_t)protocol);
  NS_ASSERT_MSG (!m_downTarget.IsNull (), "Error, YoungdsrRouting cannot send downward");
  uint8_t salvage = rerr.GetSalvage ();
  Ipv4Address dst = rerr.GetOriginalDst ();
  NS_LOG_DEBUG ("our own address here " << m_mainAddress << " error source " << rerr.GetErrorSrc () << " error destination " << rerr.GetErrorDst ()
                                        << " error next hop " << rerr.GetUnreachNode () << " original dst " << rerr.GetOriginalDst ()
                );
  YoungdsrRouteCacheEntry toDst;
  if (m_routeCache->LookupRoute (dst, toDst))
    {
      /*
       *dstルートを見つけ、ソースルートオプションヘッダーを構築します
       */
      YoungdsrOptionSRHeader sourceRoute;
      std::vector<Ipv4Address> ip = toDst.GetVector ();
      sourceRoute.SetNodesAddress (ip);
      /// When found a route and use it, UseExtends to the link cache
      if (m_routeCache->IsLinkCache ())
        {
          m_routeCache->UseExtends (ip);
        }
      sourceRoute.SetSegmentsLeft ((ip.size () - 2));
      sourceRoute.SetSalvage (salvage);
      Ipv4Address nextHop = SearchNextHop (m_mainAddress, ip);       // Get the next hop address
      NS_LOG_DEBUG ("The nextHop address " << nextHop);
      Ptr<Packet> packet = Create<Packet> ();
      if (nextHop == "0.0.0.0")
        {
          NS_LOG_DEBUG ("Error next hop address");
          PacketNewRoute (packet, m_mainAddress, dst, protocol);
          return;
        }
      SetRoute (nextHop, m_mainAddress);
      CancelRreqTimer (dst, true);
      /// 1つのルートが見つかったら、バッファからパケットを送信してみてください
      if (m_sendBuffer.GetSize () != 0 && m_sendBuffer.Find (dst))
        {
          SendPacketFromBuffer (sourceRoute, nextHop, protocol);
        }
      NS_LOG_LOGIC ("Route to " << dst << " found");
      return;
    }
  else
    {
      NS_LOG_INFO ("No route found, initiate route error request");
      Ptr<Packet> packet = Create<Packet> ();
      Ipv4Address originalDst = rerr.GetOriginalDst ();
      // Create an empty route ptr
      Ptr<Ipv4Route> route = 0;
      /*
       * ルート要求オプションヘッダーを構築します
       */
      YoungdsrRoutingHeader youngdsrRoutingHeader;
      youngdsrRoutingHeader.SetNextHeader (protocol);
      youngdsrRoutingHeader.SetMessageType (1);
      youngdsrRoutingHeader.SetSourceId (GetIDfromIP (m_mainAddress));
      youngdsrRoutingHeader.SetDestId (255);

      Ptr<Packet> dstP = Create<Packet> ();
      YoungdsrOptionRreqHeader rreqHeader;                                // has an alignment of 4n+0
      rreqHeader.AddNodeAddress (m_mainAddress);                     // Add our own address in the header
      rreqHeader.SetTarget (originalDst);
      m_requestId = m_rreqTable->CheckUniqueRreqId (originalDst);       // Check the Id cache for duplicate ones
      rreqHeader.SetId (m_requestId);

      youngdsrRoutingHeader.AddYoungdsrOption (rreqHeader);         // Add the rreqHeader to the youngdsr extension header
      youngdsrRoutingHeader.AddYoungdsrOption (rerr);
      uint8_t length = rreqHeader.GetLength () + rerr.GetLength ();
      youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 4);
      dstP->AddHeader (youngdsrRoutingHeader);
      // ルートリクエストの再試行をスケジュールし、エラーが含まれているため、ルートリクエストメッセージを伝播します。
      bool nonProp = false;
      std::vector<Ipv4Address> address;
      address.push_back (m_mainAddress);
      address.push_back (originalDst);
      /*
       * ソケットip ttlタグをパケットに追加して、ルート要求の範囲を制限します
       */
      SocketIpTtlTag tag;
      tag.SetTtl ((uint8_t)m_discoveryHopLimit);
      Ptr<Packet> propPacket = dstP->Copy ();
      propPacket->AddPacketTag (tag);

      if ((m_addressReqTimer.find (originalDst) == m_addressReqTimer.end ()) && (m_nonPropReqTimer.find (originalDst) == m_nonPropReqTimer.end ()))
        {
          NS_LOG_INFO ("Only when there is no existing route request time when the initial route request is scheduled");
          SendRequest (propPacket, m_mainAddress);
          ScheduleRreqRetry (dstP, address, nonProp, m_requestId, protocol);
        }
      else
        {
          NS_LOG_INFO ("There is existing route request, find the existing route request entry");
          /*
           * ルートリクエストをスケジュールする前に、まずルートリクエストタイマーをキャンセルします
            *この場合、ルートリクエストエントリを削除しないため、isRemove値はfalseです
           */
          CancelRreqTimer (originalDst, false);
          ScheduleRreqRetry (dstP, address, nonProp, m_requestId, protocol);
        }
    }
}

void
YoungdsrRouting::CancelRreqTimer (Ipv4Address dst, bool isRemove)
{
  NS_LOG_FUNCTION (this << dst << isRemove);
  // 見つかった場合、非伝播要求タイマーをキャンセルします
  if (m_nonPropReqTimer.find (dst) == m_nonPropReqTimer.end ())
    {
      NS_LOG_DEBUG ("Did not find the non-propagation timer");
    }
  else
    {
      NS_LOG_DEBUG ("did find the non-propagation timer");
    }
  m_nonPropReqTimer[dst].Cancel ();
  m_nonPropReqTimer[dst].Remove ();

  if (m_nonPropReqTimer[dst].IsRunning ())
    {
      NS_LOG_DEBUG ("Timer not canceled");
    }
  m_nonPropReqTimer.erase (dst);

  // Cancel the address request timer if found
  if (m_addressReqTimer.find (dst) == m_addressReqTimer.end ())
    {
      NS_LOG_DEBUG ("Did not find the propagation timer");
    }
  else
    {
      NS_LOG_DEBUG ("did find the propagation timer");
    }
  m_addressReqTimer[dst].Cancel ();
  m_addressReqTimer[dst].Remove ();
  if (m_addressReqTimer[dst].IsRunning ())
    {
      NS_LOG_DEBUG ("Timer not canceled");
    }
  m_addressReqTimer.erase (dst);
  /*
   * ルートリクエストがルートリクエストエントリを削除するようにスケジュールされている場合
    *特定の宛先に対して行われたルート再試行回数を含むルート要求エントリを削除する
   */
  if (isRemove)
    {
      // ルートリクエストテーブルからルートリクエストエントリを削除する
      m_rreqTable->RemoveRreqEntry (dst);
    }
}

void
YoungdsrRouting::ScheduleRreqRetry (Ptr<Packet> packet, std::vector<Ipv4Address> address, bool nonProp, uint32_t requestId, uint8_t protocol)
{
  NS_LOG_FUNCTION (this << packet << nonProp << requestId << (uint32_t)protocol);
  Ipv4Address source = address[0];
  Ipv4Address dst = address[1];
  if (nonProp)
    {
      // nonPropルートリクエストのみが送信され、既に使用されています
      if (m_nonPropReqTimer.find (dst) == m_nonPropReqTimer.end ())
        {
          Timer timer (Timer::CANCEL_ON_DESTROY);
          m_nonPropReqTimer[dst] = timer;
        }
      std::vector<Ipv4Address> address;
      address.push_back (source);
      address.push_back (dst);
      m_nonPropReqTimer[dst].SetFunction (&YoungdsrRouting::RouteRequestTimerExpire, this);
      m_nonPropReqTimer[dst].Remove ();
      m_nonPropReqTimer[dst].SetArguments (packet, address, requestId, protocol);
      m_nonPropReqTimer[dst].Schedule (m_nonpropRequestTimeout);
    }
  else
    {
      // Cancel the non propagation request timer if found
      m_nonPropReqTimer[dst].Cancel ();
      m_nonPropReqTimer[dst].Remove ();
      if (m_nonPropReqTimer[dst].IsRunning ())
        {
          NS_LOG_DEBUG ("Timer not canceled");
        }
      m_nonPropReqTimer.erase (dst);

      if (m_addressReqTimer.find (dst) == m_addressReqTimer.end ())
        {
          Timer timer (Timer::CANCEL_ON_DESTROY);
          m_addressReqTimer[dst] = timer;
        }
      std::vector<Ipv4Address> address;
      address.push_back (source);
      address.push_back (dst);
      m_addressReqTimer[dst].SetFunction (&YoungdsrRouting::RouteRequestTimerExpire, this);
      m_addressReqTimer[dst].Remove ();
      m_addressReqTimer[dst].SetArguments (packet, address, requestId, protocol);
      Time rreqDelay;
      // back off mechanism for sending route requests
      if (m_rreqTable->GetRreqCnt (dst))
        {
          // When the route request count is larger than 0
          // This is the exponential back-off mechanism for route request
          rreqDelay = Time (std::pow (static_cast<double> (m_rreqTable->GetRreqCnt (dst)), 2.0) * m_requestPeriod);
        }
      else
        {
          // This is the first route request retry
          rreqDelay = m_requestPeriod;
        }
      NS_LOG_LOGIC ("Request count for " << dst << " " << m_rreqTable->GetRreqCnt (dst) << " with delay time " << rreqDelay.GetSeconds () << " second");
      if (rreqDelay > m_maxRequestPeriod)
        {
          // use the max request period
          NS_LOG_LOGIC ("The max request delay time " << m_maxRequestPeriod.GetSeconds ());
          m_addressReqTimer[dst].Schedule (m_maxRequestPeriod);
        }
      else
        {
          NS_LOG_LOGIC ("The request delay time " << rreqDelay.GetSeconds () << " second");
          m_addressReqTimer[dst].Schedule (rreqDelay);
        }
    }
}

void
YoungdsrRouting::RouteRequestTimerExpire (Ptr<Packet> packet, std::vector<Ipv4Address> address, uint32_t requestId, uint8_t protocol)
{
  NS_LOG_FUNCTION (this << packet << requestId << (uint32_t)protocol);
  // Get a clean packet without youngdsr header
  Ptr<Packet> youngdsrP = packet->Copy ();
  YoungdsrRoutingHeader youngdsrRoutingHeader;
  youngdsrP->RemoveHeader (youngdsrRoutingHeader);          // Remove the youngdsr header in whole

  Ipv4Address source = address[0];
  Ipv4Address dst = address[1];
  YoungdsrRouteCacheEntry toDst;
  if (m_routeCache->LookupRoute (dst, toDst))
    {
      /*
       * Found a route the dst, construct the source route option header
       */
      YoungdsrOptionSRHeader sourceRoute;
      std::vector<Ipv4Address> ip = toDst.GetVector ();
      sourceRoute.SetNodesAddress (ip);
      // When we found the route and use it, UseExtends for the link cache
      if (m_routeCache->IsLinkCache ())
        {
          m_routeCache->UseExtends (ip);
        }
      sourceRoute.SetSegmentsLeft ((ip.size () - 2));
      /// Set the salvage value to 0
      sourceRoute.SetSalvage (0);
      Ipv4Address nextHop = SearchNextHop (m_mainAddress, ip);       // Get the next hop address
      NS_LOG_INFO ("The nextHop address is " << nextHop);
      if (nextHop == "0.0.0.0")
        {
          NS_LOG_DEBUG ("Error next hop address");
          PacketNewRoute (youngdsrP, source, dst, protocol);
          return;
        }
      SetRoute (nextHop, m_mainAddress);
      CancelRreqTimer (dst, true);
      /// Try to send out data packet from the send buffer if found
      if (m_sendBuffer.GetSize () != 0 && m_sendBuffer.Find (dst))
        {
          SendPacketFromBuffer (sourceRoute, nextHop, protocol);
        }
      NS_LOG_LOGIC ("Route to " << dst << " found");
      return;
    }
  /*
   *  If a route discovery has been attempted m_rreqRetries times at the maximum TTL without
   *  receiving any RREP, all data packets destined for the corresponding destination SHOULD be
   *  dropped from the buffer and a Destination Unreachable message SHOULD be delivered to the application.
   */
  NS_LOG_LOGIC ("The new request count for " << dst << " is " << m_rreqTable->GetRreqCnt (dst) << " the max " << m_rreqRetries);
  if (m_rreqTable->GetRreqCnt (dst) >= m_rreqRetries)
    {
      NS_LOG_LOGIC ("Route discovery to " << dst << " has been attempted " << m_rreqRetries << " times");
      CancelRreqTimer (dst, true);
      NS_LOG_DEBUG ("Route not found. Drop packet with dst " << dst);
      m_sendBuffer.DropPacketWithDst (dst);
    }
  else
    {
      SocketIpTtlTag tag;
      tag.SetTtl ((uint8_t)m_discoveryHopLimit);
      Ptr<Packet> propPacket = packet->Copy ();
      propPacket->AddPacketTag (tag);
      // Increase the request count
      m_rreqTable->FindAndUpdate (dst);
      SendRequest (propPacket, source);
      NS_LOG_DEBUG ("Check the route request entry " << source << " " << dst);
      ScheduleRreqRetry (packet, address, false, requestId, protocol);
    }
  return;
}

void
YoungdsrRouting::SendRequest (Ptr<Packet> packet,
                         Ipv4Address source)
{
  NS_LOG_FUNCTION (this << packet << source);

  NS_ASSERT_MSG (!m_downTarget.IsNull (), "Error, YoungdsrRouting cannot send downward");
  /*
   * The destination address here is directed broadcast address
   */
  uint32_t priority = GetPriority (DSR_CONTROL_PACKET);
  std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator i = m_priorityQueue.find (priority);
  Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = i->second;
  NS_LOG_LOGIC ("Inserting into priority queue number: " << priority);

  //m_downTarget (packet, source, m_broadcast, GetProtocolNumber (), 0);

  /// \todo New YoungdsrNetworkQueueEntry
  YoungdsrNetworkQueueEntry newEntry (packet, source, m_broadcast, Simulator::Now (), 0);
  if (youngdsrNetworkQueue->Enqueue (newEntry))
    {
      Scheduler (priority);
    }
  else
    {
      NS_LOG_INFO ("Packet dropped as youngdsr network queue is full");
    }
}

void
YoungdsrRouting::ScheduleInterRequest (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);
  /*
   * This is a forwarding case when sending route requests, a random delay time [0, m_broadcastJitter]
   * used before forwarding as link-layer broadcast
   */
  Simulator::Schedule (MilliSeconds (m_uniformRandomVariable->GetInteger (0, m_broadcastJitter)), &YoungdsrRouting::SendRequest, this,
                       packet, m_mainAddress);
}

void
YoungdsrRouting::SendGratuitousReply (Ipv4Address source, Ipv4Address srcAddress, std::vector<Ipv4Address> &nodeList, uint8_t protocol)
{
  NS_LOG_FUNCTION (this << source << srcAddress << (uint32_t)protocol);
  if (!(m_graReply.FindAndUpdate (source, srcAddress, m_gratReplyHoldoff)))     // Find the gratuitous reply entry
    {
      NS_LOG_LOGIC ("Update gratuitous reply " << source);
      GraReplyEntry graReplyEntry (source, srcAddress, m_gratReplyHoldoff + Simulator::Now ());
      m_graReply.AddEntry (graReplyEntry);
      /*
       * Automatic route shortening
       */
      m_finalRoute.clear ();      // Clear the final route vector
      /**
       * Push back the node addresses other than those between srcAddress and our own ip address
       */
      std::vector<Ipv4Address>::iterator before = find (nodeList.begin (), nodeList.end (), srcAddress);
      for (std::vector<Ipv4Address>::iterator i = nodeList.begin (); i != before; ++i)
        {
          m_finalRoute.push_back (*i);
        }
      m_finalRoute.push_back (srcAddress);
      std::vector<Ipv4Address>::iterator after = find (nodeList.begin (), nodeList.end (), m_mainAddress);
      for (std::vector<Ipv4Address>::iterator j = after; j != nodeList.end (); ++j)
        {
          m_finalRoute.push_back (*j);
        }
      YoungdsrOptionRrepHeader rrep;
      rrep.SetNodesAddress (m_finalRoute);           // Set the node addresses in the route reply header
      // Get the real reply source and destination
      Ipv4Address replySrc = m_finalRoute.back ();
      Ipv4Address replyDst = m_finalRoute.front ();
      /*
       * Set the route and use it in send back route reply
       */
      m_ipv4Route = SetRoute (srcAddress, m_mainAddress);
      /*
       * This part adds DSR header to the packet and send reply
       */
      YoungdsrRoutingHeader youngdsrRoutingHeader;
      youngdsrRoutingHeader.SetNextHeader (protocol);
      youngdsrRoutingHeader.SetMessageType (1);
      youngdsrRoutingHeader.SetSourceId (GetIDfromIP (replySrc));
      youngdsrRoutingHeader.SetDestId (GetIDfromIP (replyDst));

      uint8_t length = rrep.GetLength ();        // Get the length of the rrep header excluding the type header
      youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 2);
      youngdsrRoutingHeader.AddYoungdsrOption (rrep);
      Ptr<Packet> newPacket = Create<Packet> ();
      newPacket->AddHeader (youngdsrRoutingHeader);
      /*
       * Send gratuitous reply
       */
      NS_LOG_INFO ("Send back gratuitous route reply");
      SendReply (newPacket, m_mainAddress, srcAddress, m_ipv4Route);
    }
  else
    {
      NS_LOG_INFO ("The same gratuitous route reply has already sent");
    }
}

void
YoungdsrRouting::SendReply (Ptr<Packet> packet,
                       Ipv4Address source,
                       Ipv4Address nextHop,
                       Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this << packet << source << nextHop);
  NS_ASSERT_MSG (!m_downTarget.IsNull (), "Error, YoungdsrRouting cannot send downward");

  Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (m_mainAddress));
  route->SetOutputDevice (dev);
  NS_LOG_INFO ("The output device " << dev << " packet is: " << *packet);

  uint32_t priority = GetPriority (DSR_CONTROL_PACKET);
  std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator i = m_priorityQueue.find (priority);
  Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = i->second;
  NS_LOG_INFO ("Inserting into priority queue number: " << priority);

  //m_downTarget (packet, source, nextHop, GetProtocolNumber (), route);

  /// \todo New YoungdsrNetworkQueueEntry
  YoungdsrNetworkQueueEntry newEntry (packet, source, nextHop, Simulator::Now (), route);
  if (youngdsrNetworkQueue->Enqueue (newEntry))
    {
      Scheduler (priority);
    }
  else
    {
      NS_LOG_INFO ("Packet dropped as youngdsr network queue is full");
    }
}

void
YoungdsrRouting::ScheduleInitialReply (Ptr<Packet> packet,
                                  Ipv4Address source,
                                  Ipv4Address nextHop,
                                  Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this << packet << source << nextHop);
  Simulator::ScheduleNow (&YoungdsrRouting::SendReply, this,
                          packet, source, nextHop, route);
}

void
YoungdsrRouting::ScheduleCachedReply (Ptr<Packet> packet,
                                 Ipv4Address source,
                                 Ipv4Address destination,
                                 Ptr<Ipv4Route> route,
                                 double hops)
{
  NS_LOG_FUNCTION (this << packet << source << destination);
  Simulator::Schedule (Time (2 * m_nodeTraversalTime * (hops - 1 + m_uniformRandomVariable->GetValue (0,1))), &YoungdsrRouting::SendReply, this, packet, source, destination, route);
}

void
YoungdsrRouting::SendAck   (uint16_t ackId,
                       Ipv4Address destination,
                       Ipv4Address realSrc,
                       Ipv4Address realDst,
                       uint8_t protocol,
                       Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this << ackId << destination << realSrc << realDst << (uint32_t)protocol << route);
  NS_ASSERT_MSG (!m_downTarget.IsNull (), "Error, YoungdsrRouting cannot send downward");

  // This is a route reply option header
  YoungdsrRoutingHeader youngdsrRoutingHeader;
  youngdsrRoutingHeader.SetNextHeader (protocol);
  youngdsrRoutingHeader.SetMessageType (1);
  youngdsrRoutingHeader.SetSourceId (GetIDfromIP (m_mainAddress));
  youngdsrRoutingHeader.SetDestId (GetIDfromIP (destination));

  YoungdsrOptionAckHeader ack;
  /*
   * Set the ack Id and set the ack source address and destination address
   */
  ack.SetAckId (ackId);
  ack.SetRealSrc (realSrc);
  ack.SetRealDst (realDst);

  uint8_t length = ack.GetLength ();
  youngdsrRoutingHeader.SetPayloadLength (uint16_t (length) + 2);
  youngdsrRoutingHeader.AddYoungdsrOption (ack);

  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (youngdsrRoutingHeader);
  Ptr<NetDevice> dev = m_ip->GetNetDevice (m_ip->GetInterfaceForAddress (m_mainAddress));
  route->SetOutputDevice (dev);

  uint32_t priority = GetPriority (DSR_CONTROL_PACKET);
  std::map<uint32_t, Ptr<youngdsr::YoungdsrNetworkQueue> >::iterator i = m_priorityQueue.find (priority);
  Ptr<youngdsr::YoungdsrNetworkQueue> youngdsrNetworkQueue = i->second;

  NS_LOG_LOGIC ("Will be inserting into priority queue " << youngdsrNetworkQueue << " number: " << priority);

  //m_downTarget (packet, m_mainAddress, destination, GetProtocolNumber (), route);

  /// \todo New YoungdsrNetworkQueueEntry
  YoungdsrNetworkQueueEntry newEntry (packet, m_mainAddress, destination, Simulator::Now (), route);
  if (youngdsrNetworkQueue->Enqueue (newEntry))
    {
      Scheduler (priority);
    }
  else
    {
      NS_LOG_INFO ("Packet dropped as youngdsr network queue is full");
    }
}

enum IpL4Protocol::RxStatus
YoungdsrRouting::Receive (Ptr<Packet> p,
                     Ipv4Header const &ip,
                     Ptr<Ipv4Interface> incomingInterface)
{


  NS_LOG_FUNCTION (this << p << ip << incomingInterface);

  NS_LOG_INFO ("Our own IP address " << m_mainAddress << " The incoming interface address " << incomingInterface);

  m_node = GetNode ();                        // Get the node
  Ptr<Packet> packet = p->Copy ();            // Save a copy of the received packet
  /*
   * パケットを転送またはローカル配信するときは、これを常に使用する必要があります!!
   */
  YoungdsrRoutingHeader youngdsrRoutingHeader;
  packet->RemoveHeader (youngdsrRoutingHeader);          // Remove the DSR header in whole
  Ptr<Packet> copy = packet->Copy ();

  uint8_t protocol = youngdsrRoutingHeader.GetNextHeader ();
  uint32_t sourceId = youngdsrRoutingHeader.GetSourceId ();
  Ipv4Address source = GetIPfromID (sourceId);
  NS_LOG_INFO ("The source address " << source << " with source id " << sourceId);
  /*
   * Get the IP source and destination address
   */
  Ipv4Address src = ip.GetSource ();

  bool isPromisc = false;
  uint32_t offset = youngdsrRoutingHeader.GetYoungdsrOptionsOffset ();        // Get the offset for option header, 8 bytes in this case

  // This packet is used to peek option type
  p->RemoveAtStart (offset);

  Ptr<youngdsr::YoungdsrOptions> youngdsrOption;
  YoungdsrOptionHeader youngdsrOptionHeader;
  /*
   * Peek data to get the option type as well as length and segmentsLeft field
   */
  uint32_t size = p->GetSize ();
  uint8_t *data = new uint8_t[size];
  p->CopyData (data, size);

  uint8_t optionType = 0;
  uint8_t optionLength = 0;
  uint8_t segmentsLeft = 0;

  optionType = *(data);
  NS_LOG_LOGIC ("The option type value " << (uint32_t)optionType << " with packet id " << p->GetUid ());
  youngdsrOption = GetOption (optionType);       // Get the relative youngdsr option and demux to the process function
  Ipv4Address promiscSource;      /// this is just here for the sake of passing in the promisc source
  if (optionType == 1)        // This is the request option
    {
      BlackList *blackList = m_rreqTable->FindUnidirectional (src);
      if (blackList)
        {
          ////std::cout << "パケットドロップ：アンディレクショナルなリンク" << '\n';
          NS_LOG_INFO ("Discard this packet due to unidirectional link");
          m_dropTrace (p);
        }

      youngdsrOption = GetOption (optionType);
      optionLength = youngdsrOption->Process (p, packet, m_mainAddress, source, ip, protocol, isPromisc, promiscSource);

      if (optionLength == 0)
        {
          NS_LOG_INFO ("Discard this packet");
          m_dropTrace (p);
        }
    }
  else if (optionType == 2)
    {
      youngdsrOption = GetOption (optionType);
      optionLength = youngdsrOption->Process (p, packet, m_mainAddress, source, ip, protocol, isPromisc, promiscSource);

      if (optionLength == 0)
        {
          NS_LOG_INFO ("Discard this packet");
          m_dropTrace (p);
        }
    }

  else if (optionType == 32)       // This is the ACK option
    {
      NS_LOG_INFO ("This is the ack option");
      youngdsrOption = GetOption (optionType);
      optionLength = youngdsrOption->Process (p, packet, m_mainAddress, source, ip, protocol, isPromisc, promiscSource);

      if (optionLength == 0)
        {
          NS_LOG_INFO ("Discard this packet");
          m_dropTrace (p);
        }
    }

  else if (optionType == 3)       // This is a route error header
    {
      // populate this route error
      NS_LOG_INFO ("The option type value " << (uint32_t)optionType);

      if (GetIDfromIP(m_mainAddress) == m_malicious) {
        mfailed++;
        ////std::cout << "残念！" << mfailed << '\n';
      }

      /***if (GetIDfromIP(m_mainAddress) == 23) {
        failedR++;
        std::cout << "普通のノード" << failedR << '\n';
      }
      ***/
      youngdsrOption = GetOption (optionType);
      optionLength = youngdsrOption->Process (p, packet, m_mainAddress, source, ip, protocol, isPromisc, promiscSource);

      if (optionLength == 0)
        {
          NS_LOG_INFO ("Discard this packet");
          m_dropTrace (p);
        }
      NS_LOG_INFO ("The option Length " << (uint32_t)optionLength);
    }

  else if (optionType == 96)       // This is the source route option
    {
      if (GetIDfromIP(m_mainAddress) == m_malicious) {
        mcorrect++;
      ////  std::cout << "M:成功！" << mcorrect<<  correctc << '\n';
      }
      if (GetIDfromIP(m_mainAddress) == 33) {
        correctc++;
      ////  std::cout << "normal:成功！" << correctc << '\n';
      }
      youngdsrOption = GetOption (optionType);
      optionLength = youngdsrOption->Process (p, packet, m_mainAddress, source, ip, protocol, isPromisc, promiscSource);
      segmentsLeft = *(data + 3);
      if (optionLength == 0)
        {
          NS_LOG_INFO ("Discard this packet");
          m_dropTrace (p);
        }
      else
        {
          if (segmentsLeft == 0)
            {
              // / Get the next header
              uint8_t nextHeader = youngdsrRoutingHeader.GetNextHeader ();
              Ptr<Ipv4L3Protocol> l3proto = m_node->GetObject<Ipv4L3Protocol> ();
              Ptr<IpL4Protocol> nextProto = l3proto->GetProtocol (nextHeader);
              if (nextProto != 0)
                {
                  // 万が一の場合は、コピーを作成する必要があります
                   // RX_ENDPOINT_UNREACHコードパス
                   //ここでは、DSRヘッダー全体から取得したパケットを使用できます
                  enum IpL4Protocol::RxStatus status =
                    nextProto->Receive (copy, ip, incomingInterface);
                  NS_LOG_DEBUG ("The receive status " << status);
                  switch (status)
                    {
                    case IpL4Protocol::RX_OK:
                    // fall through
                    case IpL4Protocol::RX_ENDPOINT_CLOSED:
                    // fall through
                    case IpL4Protocol::RX_CSUM_FAILED:
                      break;
                    case IpL4Protocol::RX_ENDPOINT_UNREACH:
                      if (ip.GetDestination ().IsBroadcast () == true
                          || ip.GetDestination ().IsMulticast () == true)
                        {
                          break;       // Do not reply to broadcast or multicast
                        }
                      // Another case to suppress ICMP is a subnet-directed broadcast
                    }
                  return status;
                }
              else
                {
                  NS_FATAL_ERROR ("Should not have 0 next protocol value");
                }
            }
          else
            {
              NS_LOG_INFO ("This is not the final destination, the packet has already been forward to next hop");
            }
        }
    }
  else
    {
      NS_LOG_LOGIC ("Unknown Option. Drop!");
      /*
       * Initialize the salvage value to 0
       */
      uint8_t salvage = 0;

      YoungdsrOptionRerrUnsupportHeader rerrUnsupportHeader;
      rerrUnsupportHeader.SetErrorType (3);               // The error type 3 means Option not supported
      rerrUnsupportHeader.SetErrorSrc (m_mainAddress);       // The error source address is our own address
      rerrUnsupportHeader.SetUnsupported (optionType);       // The unsupported option type number
      rerrUnsupportHeader.SetErrorDst (src);              // Error destination address is the destination of the data packet
      rerrUnsupportHeader.SetSalvage (salvage);           // Set the value about whether to salvage a packet or not

      /*
       * The unknown option error is not supported currently in this implementation, and it's also not likely to
       * happen in simulations
       */
//            SendError (rerrUnsupportHeader, 0, protocol); // Send the error packet
    }
  return IpL4Protocol::RX_OK;
}

enum IpL4Protocol::RxStatus
YoungdsrRouting::Receive (Ptr<Packet> p,
                     Ipv6Header const &ip,
                     Ptr<Ipv6Interface> incomingInterface)
{
  NS_LOG_FUNCTION (this << p << ip.GetSourceAddress () << ip.GetDestinationAddress () << incomingInterface);
  return IpL4Protocol::RX_ENDPOINT_UNREACH;
}

void
YoungdsrRouting::SetDownTarget (DownTargetCallback callback)
{
  m_downTarget = callback;
}

void
YoungdsrRouting::SetDownTarget6 (DownTargetCallback6 callback)
{
  NS_FATAL_ERROR ("Unimplemented");
}


IpL4Protocol::DownTargetCallback
YoungdsrRouting::GetDownTarget (void) const
{
  return m_downTarget;
}

IpL4Protocol::DownTargetCallback6
YoungdsrRouting::GetDownTarget6 (void) const
{
  NS_FATAL_ERROR ("Unimplemented");
  return MakeNullCallback<void,Ptr<Packet>, Ipv6Address, Ipv6Address, uint8_t, Ptr<Ipv6Route> > ();
}

void YoungdsrRouting::Insert (Ptr<youngdsr::YoungdsrOptions> option)
{
  m_options.push_back (option);
}

Ptr<youngdsr::YoungdsrOptions> YoungdsrRouting::GetOption (int optionNumber)
{
  for (YoungdsrOptionList_t::iterator i = m_options.begin (); i != m_options.end (); ++i)
    {
      if ((*i)->GetOptionNumber () == optionNumber)
        {
          return *i;
        }
    }
  return 0;
}
}  /* namespace youngdsr */
}  /* namespace ns3 */
