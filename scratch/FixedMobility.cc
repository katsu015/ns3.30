/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018 Alberto Gallegos
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
 * Author: Alberto Gallegos <ramonet@fc.ritsumei.ac.jp>
 *         Ritsumeikan University, Shiga, Japan
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
//#include "ns3/shuto-module.h"
#include "ns3/senko-module.h"
#include "ns3/sample-module.h"
#include "ns3/lsgo-module.h"
#include "ns3/shutoushu-module.h"
#include "ns3/exor-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/itu-r-1411-los-propagation-loss-model.h"
#include "ns3/ocb-wifi-mac.h"
#include "ns3/wifi-80211p-helper.h"
#include "ns3/wave-mac-helper.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/config-store-module.h"
#include "ns3/integer.h"
#include "ns3/wave-bsm-helper.h"
#include "ns3/wave-helper.h"
#include "ns3/topology.h" ///obstacle
#include "ns3/netanim-module.h"
#include "ns3/yans-wifi-helper.h"
#include <stdlib.h>
#include <stdio.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include <iomanip>

#define DIS_TIME 20.0
#define SIM_STOP 200.0
#define TH_INTERVAL 0.1
//#define NumNodes 10

//#define PROG_DIR        "ns-3.29"

NS_LOG_COMPONENT_DEFINE ("shutoTestMobility");

using namespace ns3;

class NetSim
{
public:
  NetSim ();

  virtual void Configure (StringValue);
  virtual void CreateNetworkTopology ();
  virtual void ConfigureDataLinkLayer (bool, StringValue, double);
  virtual void ConfigureNetworkLayer (uint32_t);
  virtual void ConfigureTransportLayerWithUDP (Ptr<Node>, uint32_t, Ptr<Node>, uint32_t);
  virtual void StartApplication (Ptr<Node>, DataRate, uint32_t);
  virtual void StartApplication (Ptr<Node>, uint32_t, uint32_t, double);

  Ptr<Node> *n;
  Ptr<Node> mn;

  uint32_t totalReceived;
  uint32_t totalSent;

private:
  void GenerateTrafficWithDataRate (Ptr<Socket>, uint32_t, DataRate);
  void GenerateTrafficWithPktCount (Ptr<Socket>, uint32_t, uint32_t, Time);
  void ReceivePacket (Ptr<Socket>);
  InetSocketAddress setSocketAddress (Ptr<Node>, uint32_t);

  Ptr<Socket> source;
  Ptr<Socket> destination;

  uint32_t nWifiNodes;
  NodeContainer wlanNodes;
  NodeContainer allNodes;
  NetDeviceContainer devices;
  void traceThroughput ();
};

NetSim::NetSim () : totalReceived (0), totalSent (0)
{
  nWifiNodes = 600; //動かさないノードの数
}

void
NetSim::traceThroughput ()
{
  double now = (double) Simulator::Now ().GetSeconds ();
  double th = (totalReceived * 8) / now;
  std::cout << std::setw (10) << now << "\t" << th << std::endl;
  Simulator::Schedule (Seconds (TH_INTERVAL), &NetSim::traceThroughput, this);
}

void
NetSim::ReceivePacket (Ptr<Socket> socket)
{
  Ptr<Packet> packet;
  Address from;

  while ((packet = socket->RecvFrom (from)))
    {
      if (packet->GetSize () > 0)
        {
#ifdef DEBUG
          InetSocketAddress iaddr = InetSocketAddress::ConvertFrom (from);
          std::cout << std::setw (10) << Simulator::Now ().GetSeconds () << " received "
                    << packet->GetSize () << " bytes from: (" << iaddr.GetIpv4 () << ", "
                    << iaddr.GetPort () << ")" << std::endl;
#endif
          totalReceived++;
        }
    }
}

void
NetSim::GenerateTrafficWithDataRate (Ptr<Socket> socket, uint32_t pktSize, DataRate dataRate)
{
  Time tNext (Seconds (pktSize * 8 / static_cast<double> (dataRate.GetBitRate ())));
  Ptr<Packet> newPacket = Create<Packet> (pktSize);
  socket->Send (newPacket);
  Simulator::Schedule (tNext, &NetSim::GenerateTrafficWithDataRate, this, socket, pktSize,
                       dataRate);
  totalSent++;
}

void
NetSim::GenerateTrafficWithPktCount (Ptr<Socket> socket, uint32_t pktSize, uint32_t pktCount,
                                     Time pktInterval)
{
  if (pktCount > 0)
    {
      socket->Send (Create<Packet> (pktSize));
      Simulator::Schedule (pktInterval, &NetSim::GenerateTrafficWithPktCount, this, socket, pktSize,
                           pktCount - 1, pktInterval);
      totalSent++;
    }
  else
    {
      socket->Close ();
    }
}

InetSocketAddress
NetSim::setSocketAddress (Ptr<Node> node, uint32_t port)
{
  Ipv4InterfaceAddress adr = node->GetObject<Ipv4> ()->GetAddress (1, 0);
  return InetSocketAddress (Ipv4Address (adr.GetLocal ()), port);
}

void
NetSim::Configure (StringValue phyMode)
{
  // disable fragmentation for frames below 2200 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold",
                      StringValue ("2200"));
  // turn off RTS/CTS for frames below 2200 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("2200"));
  // Fix non-unicast data rate to be the same as that of unicast
  //Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue (phyMode));
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode", phyMode); //?
}

void
NetSim::CreateNetworkTopology ()
{
  n = new Ptr<Node>[nWifiNodes]; //nWifiNodes=3
  for (uint32_t i = 0; i < nWifiNodes; ++i)
    {
      n[i] = CreateObject<Node> ();
      n[i]->AggregateObject (CreateObject<ConstantPositionMobilityModel> ());
      //ノードの再設定をしない限り、現在の位置にとどまる
      wlanNodes.Add (n[i]);
    }
  mn = CreateObject<Node> (); // create 1 mobile node

  allNodes.Add (wlanNodes);
  allNodes.Add (mn);
}

void
NetSim::ConfigureDataLinkLayer (bool verbose, StringValue phyMode, double dist)
{
  

  // The below set of helpers will help us to put together the wifi NICs we want
  WifiHelper wifi;
  if (verbose)
    wifi.EnableLogComponents (); // Turn on all Wifi logging
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);

  // Setup 802.11p stuff
  // m_phyMode ("OfdmRate6MbpsBW10MHz"),
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode", phyMode, "ControlMode",
                                phyMode);
  //
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");

  ///////////////////////////////////////distance 250 m faiding  あり
  wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel", "Exponent",
                                  DoubleValue (6.0), "ReferenceDistance", DoubleValue (35.0),
                                  "ReferenceLoss", DoubleValue (46.6777));

  wifiChannel.AddPropagationLoss ("ns3::NakagamiPropagationLossModel", "m0", DoubleValue (1), "m1",
                                  DoubleValue (1), "m2", DoubleValue (1));

  wifiChannel.AddPropagationLoss ("ns3::ObstacleShadowingPropagationLossModel");

  ////////////////////////////////////////

  std::string bldgFile =
          "./src/wave/examples/no_signal/poly_1000.xml"; 

  Topology::LoadBuildings (bldgFile);
      std::cout << "ファイル読み取り成功"
                << "\n";

  // wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  //wifiChannel.AddPropagationLoss ("ns3::RandomPropagationLossModel",
  //"The random variable used to pick a loss every time CalcRxPower is invoked.",
  // MakePointerAccessor (&RandomPropagationLossModel::90));

  //wifiChannel.AddPropagationLoss  ("ns3::LogDistancePropagationLossModel");
  //wifiChannel.AddPropagationLoss ("ns3::RangePropagationLossModel", "MaxRange", DoubleValue (250));

  // wifiChannel.AddPropagationLoss ("ns3::ns3::TwoRayGroundPropagationLossModel");
  //   wifiChannel.AddPropagationLoss ("ns3::NakagamiPropagationLossModel");

  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add a non-QoS upper mac, and disable rate control

  /*//error
        NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
	Ssid ssid = Ssid ("MySSID");*/

  Ssid ssid = Ssid ("MySSID");
  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac", "Ssid", SsidValue (ssid));
  devices = wifi.Install (wifiPhy, wifiMac, allNodes);

  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  //ユーザがノードの位置を指定
  int count = 1;
  int x = 0;
  int y = 0;
  for (uint32_t i = 0; i < nWifiNodes; ++i) //nzwifiNode = x のとき０〜ｘ−３個生成
    {
      // positionAlloc->Add (Vector (100.0, 150.0, 0.0)); // ni's position id=0
      if(i <= 299)
      {
        if(count == 50)
        {
          positionAlloc->Add (Vector (x, y, 0.0));
          x = 0;
          y += 200;
          count = 1;
          if(i == 299)
          {
            x = 0;
            y = 0;
            count = 1;
          }
        }else
        {
          positionAlloc->Add (Vector (x, y, 0.0));
          x += 20;
          count ++;
        }
      }else 
      {
        if(count == 50)
        {
          positionAlloc->Add (Vector (x, y, 0.0));
          x += 200;
          y = 0;
          count = 1;
        }else
        {
          positionAlloc->Add (Vector (x, y, 0.0));
          y += 20;
          count ++;
        }
      }
    }

  mobility.SetPositionAllocator (positionAlloc);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (wlanNodes);

  Ptr<WaypointMobilityModel> m_mob; //id=1
  m_mob = CreateObject<WaypointMobilityModel> ();
  mn->AggregateObject (m_mob);
  Waypoint wpt_start (Seconds (5.0), Vector (2070.0, 50.0, 0.0));
  m_mob->AddWaypoint (wpt_start);
  Waypoint wpt_stop (Seconds (SIM_STOP - 10), Vector (2070.0, 10 * SIM_STOP + 50, 0.0));
  m_mob->AddWaypoint (wpt_stop);
}

void
NetSim::ConfigureNetworkLayer (uint32_t protocol)
{
  // ShutoHelper shutoProtocol;
  if(protocol == 0)
  {
    SampleHelper Protocol;
    Ipv4ListRoutingHelper listrouting;
    listrouting.Add (Protocol, 10);
    InternetStackHelper internet;
    internet.SetRoutingHelper (listrouting);
    internet.Install (allNodes);
    std::cout<<"set routing protocol sample \n";
  }else if(protocol == 1)
  {
    LsgoHelper Protocol;
    Ipv4ListRoutingHelper listrouting;
    listrouting.Add (Protocol, 10);
    InternetStackHelper internet;
    internet.SetRoutingHelper (listrouting);
    internet.Install (allNodes);
    std::cout<<"set routing protocol lsgo \n";
  }else {
    ShutoushuHelper Protocol;
    Ipv4ListRoutingHelper listrouting;
    listrouting.Add (Protocol, 10);
    InternetStackHelper internet;
    internet.SetRoutingHelper (listrouting);
    internet.Install (allNodes);    std::cout<<"set routing protocol sigo \n";
  }
  

  Ipv4AddressHelper ipv4;
  NS_LOG_INFO ("aaaaaaaaaaaa");
  ipv4.SetBase ("10.1.0.0", "255.255.0.0");
  Ipv4InterfaceContainer ifs = ipv4.Assign (devices);
}

void
NetSim::ConfigureTransportLayerWithUDP (Ptr<Node> src, uint32_t src_port, Ptr<Node> dst,
                                        uint32_t dst_port)
{
  //ConfigureTransportLayerWithUDP(sim.n[0], 8888, sim.mn, 8888);
  // set receiver(mn)'s socket
  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");

  Ptr<Socket> destination = Socket::CreateSocket (dst, tid);
  InetSocketAddress dstSocketAddr = setSocketAddress (dst, dst_port);
  destination->Bind (dstSocketAddr);
  destination->SetRecvCallback (MakeCallback (&NetSim::ReceivePacket, this));

  // set sender(n0)'s socket
  //Ptr<Socket> source = Socket::CreateSocket (src, tid);
  source = Socket::CreateSocket (src, tid);
  InetSocketAddress srcSocketAddr = setSocketAddress (src, src_port);
  source->Bind (srcSocketAddr);
  source->SetAllowBroadcast (true);
  source->Connect (dstSocketAddr);
}

void
NetSim::StartApplication (Ptr<Node> src, DataRate dataRate, uint32_t packetSize)
{
  Simulator::ScheduleWithContext (src->GetId (), Seconds (0.1),
                                  &NetSim::GenerateTrafficWithDataRate, this, NetSim::source,
                                  packetSize, dataRate);
  Simulator::Schedule (Seconds (TH_INTERVAL), &NetSim::traceThroughput, this);
}

void
NetSim::StartApplication (Ptr<Node> src, uint32_t packetSize, uint32_t numPkt, double interval)
{
  Time interPacketInterval = Seconds (interval);
  Simulator::ScheduleWithContext (src->GetId (), Seconds (0.1),
                                  &NetSim::GenerateTrafficWithPktCount, this, NetSim::source,
                                  packetSize, numPkt, interPacketInterval);
}

int
main (int argc, char *argv[])
{
  NetSim sim;

  std::string animFile = "fixedmobiiltytest"; //netanim

  std::string phyMode ("DsssRate11Mbps"); //?
  bool verbose = false;
  bool sendFlag = false; // send pkts with dataRate
  DataRate dataRate = DataRate ("512Kbps");
  uint32_t packetSize = 512; // bytes
  uint32_t numPackets = 10;
  double distance = 150.0; // distance from mobile node
  double interval = 0.1; // seconds
  uint32_t protocol = 0;

  CommandLine cmd;
  //以下の変数は拡張可能 ex packetSize=~

  // simulatin 実行コマンド
  // ./waf --run "FixedMobility --protocol=1"
  cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
  cmd.AddValue ("packetSize", "size of application packet sent", packetSize);
  cmd.AddValue ("dataRate", "dataRate of application packet sent", dataRate);
  cmd.AddValue ("distance", "distance between STA and MN", distance);
  cmd.AddValue ("numPackets", "number of packets generated", numPackets);
  cmd.AddValue ("interval", "interval (seconds) between packets", interval);
  cmd.AddValue ("sendFlag", "send flag (1: use pkt data rate, 0: use number of pkts)", sendFlag);
  cmd.AddValue ("verbose", "turn on all WifiNetDevice log components", verbose);
  cmd.AddValue ("protocol", "select protocol 0=sample , 1= lsgo, 2= sigo", protocol);
  cmd.Parse (argc, argv);

  sim.Configure (phyMode);

  sim.CreateNetworkTopology ();

  sim.ConfigureDataLinkLayer (verbose, phyMode, distance);

  sim.ConfigureNetworkLayer (protocol);
  sim.ConfigureTransportLayerWithUDP (sim.n[0], 8888, sim.mn, 8888);

  if (sendFlag)
    sim.StartApplication (sim.n[0], dataRate, packetSize);
  else
    sim.StartApplication (sim.n[0], packetSize, numPackets, interval);

  //std::string xf = std::string(PROG_DIR) + "shutospeed.xml";
  //AnimationInterface anim (xf);
  //anim.EnablePacketMetadata (true);

  //

  Ptr<UniformRandomVariable> e = CreateObject<UniformRandomVariable> ();

  Simulator::Stop (Seconds (SIM_STOP));
  AnimationInterface anim (animFile);

  for (int i = 0; i < 22; i++)
    {
      anim.UpdateNodeSize (i, 10, 1);
    }

  anim.EnablePacketMetadata ();
  anim.EnableIpv4L3ProtocolCounters (Seconds (0), Seconds (500));

  Simulator::Run ();
  Simulator::Destroy ();

  //NS_LOG_UNCOND ("    Total packets sent: " << sim.totalSent);
  //NS_LOG_UNCOND ("Total packets received: " << sim.totalReceived);

  return 0;
}