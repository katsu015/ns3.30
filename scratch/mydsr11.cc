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

#include <sstream>
#include <iostream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/internet-module.h"
#include "ns3/youngdsr-module.h"
//#include "ns3/dsr-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/netanim-module.h"


using namespace ns3;


NS_LOG_COMPONENT_DEFINE ("DsrTest");

int main (int argc, char *argv[])
{
  std::string animFile = "mydsrtest.xml";
  //
  // Users may find it convenient to turn on explicit debugging
  // for selected modules; the below lines suggest how to do this
  //
//#if 0
/*
  LogComponentEnable ("Ipv4L3Protocol", LOG_LEVEL_ALL);
  LogComponentEnable ("UdpL4Protocol", LOG_LEVEL_ALL);
  LogComponentEnable ("UdpSocketImpl", LOG_LEVEL_ALL);
  LogComponentEnable ("NetDevice", LOG_LEVEL_ALL);
  LogComponentEnable ("Ipv4EndPointDemux", LOG_LEVEL_ALL);
  */
//#endif

#if 0
 LogComponentEnable ("YoungdsrOptions", LOG_LEVEL_FUNCTION);
/*  LogComponentEnable ("DsrHelper", LOG_LEVEL_ALL);
*/
//LogComponentEnableAll (LOG_PREFIX_TIME);
//LogComponentEnableAll (LOG_PREFIX_FUNC);
//  LogComponentEnable ("DsrRouting", LOG_LEVEL_FUNCTION);
  /*LogComponentEnable ("DsrOptionHeader", LOG_LEVEL_ALL);
  LogComponentEnable ("DsrFsHeader", LOG_LEVEL_ALL);
  LogComponentEnable ("DsrGraReplyTable", LOG_LEVEL_ALL);
  LogComponentEnable ("DsrSendBuffer", LOG_LEVEL_ALL);
  LogComponentEnable ("DsrRouteCache", LOG_LEVEL_ALL);
  LogComponentEnable ("DsrMaintainBuffer", LOG_LEVEL_ALL);
  LogComponentEnable ("DsrRreqTable", LOG_LEVEL_ALL);
  LogComponentEnable ("DsrErrorBuffer", LOG_LEVEL_ALL);
  LogComponentEnable ("DsrNetworkQueue", LOG_LEVEL_ALL);
  */
#endif

  NS_LOG_INFO ("creating the nodes");

  // General parameters
  uint32_t nWifis = 13;
  uint32_t nSinks = 4;
  //ソースノードの数
//  uint32_t nSources = 5;
  double TotalTime = 500.0;
  double dataTime = 500.0;
  double ppers = 1;
  uint32_t packetSize = 512;
  double dataStart = 0.0; // start sending data at 100s
  uint32_t seed = 1;
  uint32_t Runset = 1;

  //mobility parameters
  double pauseTime = 0.0;
  double nodeSpeed = 20.0;
  double txpDistance = 250.0;

  std::string rate = "0.512kbps";
  std::string dataMode ("DsssRate11Mbps");
  std::string phyMode ("DsssRate11Mbps");
  std::string rtslimit = "512";

  //Allow users to override the default parameters and set it to new ones from CommandLine.
  CommandLine cmd;
  cmd.AddValue ("seed", "set seed", seed);
  cmd.AddValue ("Runset", "set Run", Runset);
  cmd.AddValue ("nWifis", "Number of wifi nodes", nWifis);
  cmd.AddValue ("nSinks", "Number of SINK traffic nodes", nSinks);
  cmd.AddValue ("rate", "CBR traffic rate(in kbps), Default:8", rate);
  cmd.AddValue ("nodeSpeed", "Node speed in RandomWayPoint model, Default:20", nodeSpeed);
  cmd.AddValue ("packetSize", "The packet size", packetSize);
  cmd.AddValue ("txpDistance", "Specify node's transmit range, Default:300", txpDistance);
  cmd.AddValue ("pauseTime", "pauseTime for mobility model, Default: 0", pauseTime);
//  cmd.AddValue ("rtslimit", "RTS/CTS Threshold (bytes)", rtslimit);
  cmd.Parse (argc, argv);

  SeedManager::SetSeed (seed);
  SeedManager::SetRun (Runset);

  NodeContainer adhocNodes;
  adhocNodes.Create (nWifis);
  NetDeviceContainer allDevices;

  NS_LOG_INFO ("setting the default phy and channel parameters");
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue (phyMode));
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue (rtslimit));
  // disable fragmentation for frames below 2200 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue ("2200"));

  NS_LOG_INFO ("setting the default phy and channel parameters ");
  WifiHelper wifi;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();

  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::RangePropagationLossModel", "MaxRange", DoubleValue (txpDistance));
  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add a mac and disable rate control
  WifiMacHelper wifiMac;
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode", StringValue (dataMode), "ControlMode",
                                StringValue (phyMode));

  wifiMac.SetType ("ns3::AdhocWifiMac");
  allDevices = wifi.Install (wifiPhy, wifiMac, adhocNodes);

  NS_LOG_INFO ("Configure Tracing.");

  AsciiTraceHelper ascii;
  Ptr<OutputStreamWrapper> stream = ascii.CreateFileStream ("dsrtest.tr");
  wifiPhy.EnableAsciiAll (stream);

  MobilityHelper adhocMobility;
  ObjectFactory pos;
  pos.SetTypeId ("ns3::ListPositionAllocator");
//  pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));
  //pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]"));

//  Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
  Ptr<ListPositionAllocator> posList = CreateObject<ListPositionAllocator> ();

  posList->Add (Vector (73, 300, 0)); //node0
  posList->Add (Vector (223, 400, 0)); //node1
  posList->Add (Vector (373, 400, 0)); //node2
  posList->Add (Vector (523, 400, 0)); //node3
  posList->Add (Vector (683, 300, 0));
  posList->Add (Vector (133, 450, 0)); //node5
  posList->Add (Vector (373, 550, 0));
  posList->Add (Vector (613, 450, 0)); //node7
  posList->Add (Vector (373, 250, 0));
  posList->Add (Vector (33, 650, 0)); //node9
  posList->Add (Vector (373, 750, 0));
  posList->Add (Vector (713, 650, 0)); //node11
  posList->Add (Vector (373, 50, 0));

  adhocMobility.SetPositionAllocator(posList);


  std::ostringstream speedUniformRandomVariableStream;
  speedUniformRandomVariableStream << "ns3::UniformRandomVariable[Min=0.0|Max="
                                   << nodeSpeed
                                   << "]";

  std::ostringstream pauseConstantRandomVariableStream;
  pauseConstantRandomVariableStream << "ns3::ConstantRandomVariable[Constant="
                                    << pauseTime
                                    << "]";

  adhocMobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel"
                                  //                                  "Speed", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=nodeSpeed]"),
                                  /*"Speed", StringValue (speedUniformRandomVariableStream.str ()),
                                  "Pause", StringValue (pauseConstantRandomVariableStream.str ()),
                                  "PositionAllocator", PointerValue (taPositionAlloc)*/
                                );
  adhocMobility.Install (adhocNodes);

  InternetStackHelper internet;

  //DsrMainHelper dsrMain;
  YoungdsrMainHelper dsrMain;
  //DsrHelper dsr;
  YoungdsrHelper dsr;

  internet.Install (adhocNodes);
  dsrMain.Install (dsr, adhocNodes);

  NS_LOG_INFO ("assigning ip address");
  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer allInterfaces;
  allInterfaces = address.Assign (allDevices);

  uint16_t port = 9;
  double randomStartTime = (1 / ppers) / nSinks; //distributed btw 1s evenly as we are sending 4pkt/s

//シンクノードとソースノードを対応させる
      PacketSinkHelper sink1 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
      ApplicationContainer apps_sink1 = sink1.Install (adhocNodes.Get (9));
      apps_sink1.Start (Seconds (0.0));
      apps_sink1.Stop (Seconds (TotalTime));

  for (uint32_t i = 0; i < 3; ++i)
    {

      OnOffHelper onoff1 ("ns3::UdpSocketFactory", Address (InetSocketAddress (allInterfaces.GetAddress (9), port)));
      onoff1.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
      onoff1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
      onoff1.SetAttribute ("PacketSize", UintegerValue (packetSize));
      onoff1.SetAttribute ("DataRate", DataRateValue (DataRate (rate)));

      ApplicationContainer apps1 = onoff1.Install (adhocNodes.Get (i));
      apps1.Start (Seconds (dataStart + 9 * randomStartTime));
      apps1.Stop (Seconds (dataTime + 9 * randomStartTime));
    }

      PacketSinkHelper sink2 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
      ApplicationContainer apps_sink2 = sink2.Install (adhocNodes.Get (10));
      apps_sink2.Start (Seconds (0.0));
      apps_sink2.Stop (Seconds (TotalTime));

  for (uint32_t i = 1; i < 4; ++i)
    {
      OnOffHelper onoff2 ("ns3::UdpSocketFactory", Address (InetSocketAddress (allInterfaces.GetAddress (10), port)));
      onoff2.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
      onoff2.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
      onoff2.SetAttribute ("PacketSize", UintegerValue (packetSize));
      onoff2.SetAttribute ("DataRate", DataRateValue (DataRate (rate)));

      ApplicationContainer apps2 = onoff2.Install (adhocNodes.Get (i));
      apps2.Start (Seconds (dataStart + 10 * randomStartTime));
      apps2.Stop (Seconds (dataTime + 10 * randomStartTime));
    }


    PacketSinkHelper sink3 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
    ApplicationContainer apps_sink3 = sink3.Install (adhocNodes.Get (11));
    apps_sink3.Start (Seconds (0.0));
    apps_sink3.Stop (Seconds (TotalTime));

  for (uint32_t i = 2; i < 5; ++i)
    {
      OnOffHelper onoff3 ("ns3::UdpSocketFactory", Address (InetSocketAddress (allInterfaces.GetAddress (11), port)));
      onoff3.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
      onoff3.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
      onoff3.SetAttribute ("PacketSize", UintegerValue (packetSize));
      onoff3.SetAttribute ("DataRate", DataRateValue (DataRate (rate)));

      ApplicationContainer apps3 = onoff3.Install (adhocNodes.Get (i));
      apps3.Start (Seconds (dataStart + 11 * randomStartTime));
      apps3.Stop (Seconds (dataTime + 11 * randomStartTime));
    }

    PacketSinkHelper sink4 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
    ApplicationContainer apps_sink4 = sink4.Install (adhocNodes.Get (12));
    apps_sink4.Start (Seconds (0.0));
    apps_sink4.Stop (Seconds (TotalTime));

  for (uint32_t i = 1; i < 4; ++i)
    {
      OnOffHelper onoff4 ("ns3::UdpSocketFactory", Address (InetSocketAddress (allInterfaces.GetAddress (12), port)));
      onoff4.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
      onoff4.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
      onoff4.SetAttribute ("PacketSize", UintegerValue (packetSize));
      onoff4.SetAttribute ("DataRate", DataRateValue (DataRate (rate)));

      ApplicationContainer apps4 = onoff4.Install (adhocNodes.Get (i));
      apps4.Start (Seconds (dataStart + 12 * randomStartTime));
      apps4.Stop (Seconds (dataTime + 12 * randomStartTime));
    }

  //  }

  /*  for (uint32_t i = 0; i < nSources; ++i)
      {
        Ptr<Socket> source = Socket::CreateSocket (networkNodes.Get (i), tid);    // node 0, sender
        InetSocketAddress remote = InetSocketAddress (Ipv4Address::GetBroadcast (), 80);
        source->SetAllowBroadcast (true);
        source->Connect (remote);

        u_int32_t numPackets = 3;

        NS_LOG_UNCOND ("Testing " << numPackets << " packets sent with receiver rss " << rss );
        Time interPacketInterval = Seconds (3);
        Simulator::ScheduleWithContext (source->GetNode ()->GetId (),
      seconds (5.0), &GenerateTraffic, source, 1000, numPackets, interPacketInterval);
      }
*/



  NS_LOG_INFO ("Run Simulation.");
    wifiPhy.EnablePcapAll("mydsr11p");
  Simulator::Stop (Seconds (TotalTime));
/*
  AnimationInterface anim(animFile);
  for (uint32_t i = 0; i < nWifis; ++i)
    {
      anim.UpdateNodeSize(i,10,10);
    }
  anim.EnablePacketMetadata();
  anim.EnableIpv4L3ProtocolCounters(Seconds(0),Seconds(500));

*/

  Simulator::Run ();
  Simulator::Destroy ();

}
