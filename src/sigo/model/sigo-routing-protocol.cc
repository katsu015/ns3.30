/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 IITP RAS
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
 * 
 * 
 * 
 * 
 * チェック項目　ノード数　シミュレーション時間　ブロードキャスト開始時間　ファイル読み取りのファイル名
 *
 */
#define NS_LOG_APPEND_CONTEXT                                                \
  if (m_ipv4)                                                                \
    {                                                                        \
      std::clog << "[node " << m_ipv4->GetObject<Node> ()->GetId () << "] "; \
    }

#include "sigo-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/boolean.h"
#include "ns3/random-variable-stream.h"
#include "ns3/inet-socket-address.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/udp-header.h"
#include "ns3/wifi-net-device.h"
#include "ns3/adhoc-wifi-mac.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include "../../shutoushu/model/shutoushu-routing-protocol.h"
#include <algorithm>
#include <limits>
#include <math.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <random>
#include <numeric>
#include <iterator>
#include <sys/stat.h> // stat

#include "ns3/mobility-module.h"

int Buildings = 0; //grobal変数

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("SigoRoutingProtocol");

namespace sigo {
NS_OBJECT_ENSURE_REGISTERED (RoutingProtocol);

/// UDP Port for SIGO control traffic
const uint32_t RoutingProtocol::SIGO_PORT = 654;

//グローバル変数
int numVehicle = 0; //車両数
int roadCenterPointX[113]; //道路の中心x座標を格納
int roadCenterPointY[113]; //道路の中心y座標を格納
int packetCount = 0; //パケット出力数のカウント
int sendpacketCount = 0; //sendpacket 出力数のカウント
int maxLenge = 0; // 受信者との距離マックス

RoutingProtocol::RoutingProtocol ()
{
}

TypeId
RoutingProtocol::GetTypeId (void)
{
  static TypeId tid =
      TypeId ("ns3::sigo::RoutingProtocol")
          .SetParent<Ipv4RoutingProtocol> ()
          .SetGroupName ("Sigo")
          .AddConstructor<RoutingProtocol> ()
          .AddAttribute ("UniformRv", "Access to the underlying UniformRandomVariable",
                         StringValue ("ns3::UniformRandomVariable"),
                         MakePointerAccessor (&RoutingProtocol::m_uniformRandomVariable),
                         MakePointerChecker<UniformRandomVariable> ());
  return tid;
}

RoutingProtocol::~RoutingProtocol ()
{
}

void
RoutingProtocol::DoDispose ()
{
}

void
RoutingProtocol::PrintRoutingTable (Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
  *stream->GetStream () << "Node: " << m_ipv4->GetObject<Node> ()->GetId ()
                        << "; Time: " << Now ().As (unit)
                        << ", Local time: " << GetObject<Node> ()->GetLocalTime ().As (unit)
                        << ", SIGO Routing table" << std::endl;

  //Print routing table here.
  *stream->GetStream () << std::endl;
}

int64_t
RoutingProtocol::AssignStreams (int64_t stream)
{
  NS_LOG_FUNCTION (this << stream);
  m_uniformRandomVariable->SetStream (stream);
  return 1;
}

Ptr<Ipv4Route>
RoutingProtocol::RouteOutput (Ptr<Packet> p, const Ipv4Header &header, Ptr<NetDevice> oif,
                              Socket::SocketErrno &sockerr)
{

  //std::cout<<"Route Ouput Node: "<<m_ipv4->GetObject<Node> ()->GetId ()<<"\n";
  Ptr<Ipv4Route> route;

  if (!p)
    {
      std::cout << "loopback occured! in routeoutput";
      return route; // LoopbackRoute (header,oif);
    }

  if (m_socketAddresses.empty ())
    {
      sockerr = Socket::ERROR_NOROUTETOHOST;
      NS_LOG_LOGIC ("No zeal interfaces");
      std::cout << "RouteOutput No zeal interfaces!!, packet drop\n";

      Ptr<Ipv4Route> route;
      return route;
    }

  return route;
}

bool
RoutingProtocol::RouteInput (Ptr<const Packet> p, const Ipv4Header &header,
                             Ptr<const NetDevice> idev, UnicastForwardCallback ucb,
                             MulticastForwardCallback mcb, LocalDeliverCallback lcb,
                             ErrorCallback ecb)
{

  std::cout << "Route Input Node: " << m_ipv4->GetObject<Node> ()->GetId () << "\n";
  return true;
}

void
RoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4)
{
  NS_ASSERT (ipv4 != 0);
  NS_ASSERT (m_ipv4 == 0);
  m_ipv4 = ipv4;
}

void
RoutingProtocol::NotifyInterfaceUp (uint32_t i)
{
  NS_LOG_FUNCTION (this << m_ipv4->GetAddress (i, 0).GetLocal () << " interface is up");
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  Ipv4InterfaceAddress iface = l3->GetAddress (i, 0);
  if (iface.GetLocal () == Ipv4Address ("127.0.0.1"))
    {
      return;
    }
  // Create a socket to listen only on this interface
  Ptr<Socket> socket;

  socket = Socket::CreateSocket (GetObject<Node> (), UdpSocketFactory::GetTypeId ());
  NS_ASSERT (socket != 0);
  socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvSigo, this));
  socket->BindToNetDevice (l3->GetNetDevice (i));
  socket->Bind (InetSocketAddress (iface.GetLocal (), SIGO_PORT));
  socket->SetAllowBroadcast (true);
  socket->SetIpRecvTtl (true);
  m_socketAddresses.insert (std::make_pair (socket, iface));

  // create also a subnet broadcast socket
  socket = Socket::CreateSocket (GetObject<Node> (), UdpSocketFactory::GetTypeId ());
  NS_ASSERT (socket != 0);
  socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvSigo, this));
  socket->BindToNetDevice (l3->GetNetDevice (i));
  socket->Bind (InetSocketAddress (iface.GetBroadcast (), SIGO_PORT));
  socket->SetAllowBroadcast (true);
  socket->SetIpRecvTtl (true);
  m_socketSubnetBroadcastAddresses.insert (std::make_pair (socket, iface));

  if (m_mainAddress == Ipv4Address ())
    {
      m_mainAddress = iface.GetLocal ();
    }

  NS_ASSERT (m_mainAddress != Ipv4Address ());

  /*  for (uint32_t i = 0; i < m_ipv4->GetNInterfaces (); i++)
        {

          // Use primary address, if multiple
          Ipv4Address addr = m_ipv4->GetAddress (i, 0).GetLocal ();
        //  std::cout<<"############### "<<addr<<" |ninterface "<<m_ipv4->GetNInterfaces ()<<"\n";
       

              TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
              Ptr<Node> theNode = GetObject<Node> ();
              Ptr<Socket> socket = Socket::CreateSocket (theNode,tid);
              InetSocketAddress inetAddr (m_ipv4->GetAddress (i, 0).GetLocal (), SIGO_PORT);
              if (socket->Bind (inetAddr))
                {
                  NS_FATAL_ERROR ("Failed to bind() ZEAL socket");
                }
              socket->BindToNetDevice (m_ipv4->GetNetDevice (i));
              socket->SetAllowBroadcast (true);
              socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvSigo, this));
              //socket->SetAttribute ("IpTtl",UintegerValue (1));
              socket->SetRecvPktInfo (true);

              m_socketAddresses[socket] = m_ipv4->GetAddress (i, 0);

              //  NS_LOG_DEBUG ("Socket Binding on ip " << m_mainAddress << " interface " << i);

              break;
           
        }
*/
}

void
RoutingProtocol::NotifyInterfaceDown (uint32_t i)
{
}

void
RoutingProtocol::NotifyAddAddress (uint32_t i, Ipv4InterfaceAddress address)
{
}

void
RoutingProtocol::NotifyRemoveAddress (uint32_t i, Ipv4InterfaceAddress address)
{
}

void
RoutingProtocol::DoInitialize (void)
{
  int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  //int32_t time = Simulator::Now ().GetMicroSeconds ();
  numVehicle++;

  for (int i = 1; i < SimTime; i++)
    {
      Simulator::Schedule (Seconds (i), &RoutingProtocol::SetMyPos, this);
      if (i >= 2)
        {
          Simulator::Schedule (Seconds (i), &RoutingProtocol::SetMySpeed, this);
        }
      if (id != 0)
        {
          Simulator::Schedule (Seconds (i), &RoutingProtocol::SendHelloPacket, this);
        }
    }

  if (id == 0)
    {
      ///やることリスト
      ///送信者rのIDと位置情報をパケットに加える　車両数を ReadFile関数で読み取れるようにする
      ReadSumoFile ();
      RoadCenterPoint ();
      Simulator::Schedule (Seconds (Grobal_StartTime - 2), &RoutingProtocol::SourceAndDestination,
                           this);
      std::cout << "\n \n buildings" << Buildings << "\n";
      std::cout << "\n \n grobal seed" << Grobal_Seed << "\n";
      std::cout << "\n \n grobal startTime" << Grobal_StartTime << "\n";
      std::cout << "\n \n grobal " << Grobal_SourceNodeNum << "\n";
    }

  //**結果出力******************************************//
  for (int i = 1; i < SimTime; i++)
    {
      if (id == 0)
        Simulator::Schedule (Seconds (i), &RoutingProtocol::SimulationResult,
                             this); //結果出力関数
    }

  // Simulator::Schedule (Seconds (2.6), &RoutingProtocol::TestSend, this);

  for (int i = 0; i < Grobal_SourceNodeNum; i++)
    {
      Simulator::Schedule (Seconds (Grobal_StartTime + i * 1), &RoutingProtocol::Send, this);
    }
  /////////////////////////////random
}

void
RoutingProtocol::SourceAndDestination ()
{
  std::cout << "source and                        destination function\n";
  std::cout << "NumVehicle" << numVehicle << "\n";

  //source list と destination listに存在するノードを抽出
  for (int i = 0; i < numVehicle; i++) ///node数　設定する
    {
      if (m_my_posx[i] >= SourceLowX && m_my_posx[i] <= SourceHighX && m_my_posy[i] >= SourceLowY &&
          m_my_posy[i] <= SourceHighY)
        {
          source_list.push_back (i);
          std::cout<<"source list id" << i << "position x"<<m_my_posx[i]<<"y"<<m_my_posy[i]<<"\n";
        }
      if (m_my_posx[i] >= DesLowX && m_my_posx[i] <= DesHighX && m_my_posy[i] >= DesLowY &&
          m_my_posy[i] <= DesHighY)
        {
          des_list.push_back (i);
          std::cout<<"destination list id" << i << "position x"<<m_my_posx[i]<<"y"<<m_my_posy[i]<<"\n";
        }
    }

  //random seedを用いて並び替え
  std::mt19937 get_rand_mt (Grobal_Seed);

  std::shuffle (source_list.begin (), source_list.end (), get_rand_mt);
  std::shuffle (des_list.begin (), des_list.end (), get_rand_mt);

 //上から grobal_sourcenodenum値　抽出
  for (int i = 0; i < Grobal_SourceNodeNum; i++)
    {
      std::cout << "shuffle source id" << source_list[i] << "\n";
      std::cout << "shuffle destination id" << des_list[i] << "\n";
    }
}

void
RoutingProtocol::TestSend ()
{
  int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  int test_id = 76;

  if(id == test_id)
  {
    // Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
    // Vector mypos = mobility->GetPosition (); //broadcastするノードの位置情報
    int32_t des_id = 125;
    int32_t des_x = 500;
    int32_t des_y = 400;
    // int32_t one_before_x = 520;
    // int32_t one_before_y = 200;

    // SendSigoRecoveryBroadcast (1, des_id, des_x, des_y, mypos.x, mypos.y, 1, 
    //       one_before_x, one_before_y, one_before_x, one_before_y);
    FirstSendSigoBroadcast(0,des_id, des_x, des_y,1);
  }
}


void
RoutingProtocol::Send ()
{
  int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  int time = Simulator::Now ().GetSeconds ();

  if (time >= Grobal_StartTime)
    {
      if (id == source_list[time - Grobal_StartTime])
        {
          int index_time =
              time -
              Grobal_StartTime; //example time16 simstarttime15のときm_source_id = 1 すなわち２つめのsourceid

          Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
          Vector mypos = mobility->GetPosition ();
          int MicroSeconds = Simulator::Now ().GetMicroSeconds ();
          m_start_time[des_list[index_time]] = MicroSeconds + 300000; //秒数をずらし多分足す
          std::cout << "m_start_time" << m_start_time[des_list[index_time]] << "\n";
          double shift_time = 0.3; //送信時間を0.1秒ずらす

          //SendSigoBroadcast (0, des_list[index_time], m_my_posx[des_list[index_time]], m_my_posy[des_list[index_time]], 1);
          Simulator::Schedule (Seconds (shift_time), &RoutingProtocol::FirstSendSigoBroadcast, this, 0,
                               des_list[index_time], m_my_posx[des_list[index_time]],
                               m_my_posy[des_list[index_time]], 1);
          
          std::cout << "\n\n\n\n  " << "source node" << id << 
          "destination node " << des_list[index_time] << "\n\n";
          std::cout << "\n\n\n\n\nsource node point x=" << mypos.x << "y=" << mypos.y
                    << "des node point x=" << m_my_posx[des_list[index_time]]
                    << "y=" << m_my_posy[des_list[index_time]] << "\n\n\n\n\n";

          // Simulator::Schedule (MicroSeconds (wait_time), &RoutingProtocol::SendToSigo, this,
          //                          socket, packet, destination, hopcount, des_id);
        }
    }
}

//**window size 以下のhello message の取得回数と　初めて取得した時間を保存する関数**//
void
RoutingProtocol::SetCountTimeMap (void)
{
  int32_t current_time = Simulator::Now ().GetMicroSeconds ();
  int count = 0; //取得回数のカウント変数 この関数が呼び出されるたびに０に初期化
  int check_id = -1; //MAPのIDが変化するタイミングを調べる変数
  for (auto itr = m_recvtime.begin (); itr != m_recvtime.end (); itr++)
    {
      if (check_id == -1) //一番最初にこのループに入ったときの処理
        {
          int32_t dif_time = 0;
          dif_time = current_time - itr->second; //現在の時刻とmapの取得時刻を比較
          if (dif_time < WindowSize)
            {
              check_id = itr->first; //keyを代入
              m_first_recv_time[itr->first] = itr->second; //ループの最初　＝　最初のhello取得時間
              count = 1;
            }
        }
      else
        {
          if (check_id != itr->first) //ループ中のkeyが変わった時
            {
              int32_t dif_time = 0;
              dif_time = current_time - itr->second; //現在の時刻とmapの取得時刻を比較
              //std::cout << "current time" << current_time << "\n";
              //std::cout << "dif_time" << dif_time << "\n";
              if (dif_time < WindowSize)
                {
                  m_first_recv_time[itr->first] = itr->second;
                }
              count = 1; //カウント変数の初期化
              check_id = itr->first; //新しいkeyを代入
              m_recvcount[check_id] = count; //カウント変数を代入
            }
          else
            {
              int32_t dif_time = 0;
              dif_time = current_time - itr->second; //現在の時刻とmapの取得時刻を比較
              //std::cout << "current time" << current_time << "\n";
              //std::cout << "dif_time" << dif_time << "\n";
              if (dif_time < WindowSize) //時間の差がウィンドウサイズ以内だったら
                {
                  auto itr2 = m_first_recv_time.find (itr->first); // キーitr->firstを検索
                  if (itr2 == m_first_recv_time.end ()) //使ったら削除する
                    { // 見つからなかった場合
                      m_first_recv_time[itr->first] = itr->second;
                    }
                  count++; //keyが変わらずループが回っている時カウント変数を加算していく
                  m_recvcount[check_id] = count; //カウント変数を代入
                }
            }
        }

      // int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
      // std::cout << "id" << id << "    current time" << current_time;
      // std::cout << " send node has recvmap  = " << itr->first // キーを表示
      //           << " time  = " << itr->second << "\n"; // 値を表示
    }
}

void
RoutingProtocol::SetEtxMap (void) //////ETXをセットする関数
{
  int32_t current_time = Simulator::Now ().GetMicroSeconds ();
  //current_time = current_time / 1000000; //secondになおす

  for (auto itr = m_first_recv_time.begin (); itr != m_first_recv_time.end (); itr++)
    {
      //double micro_second = 1000000;
      double diftime; //論文のt-t0と同意
      double first_recv = (double) itr->second;
      diftime = (current_time - first_recv) / 1000000;
      //difftime = difftime / 1000000;
      //std::cout << "id" << itr->first << "dif_time" << diftime << "\n";
      double rt = (double) m_recvcount[itr->first] / diftime; //論文のrtの計算
      //std::cout << "id" << itr->first << "のrtは" << rt << "rt*rt" << rt * rt << "\n";
      if (rt > 1)
        rt = 1.0;
      m_rt[itr->first] = rt;
      double etx = 1.000000 / (rt * rt);
      if (etx < 1)
        etx = 1;
      m_etx[itr->first] = etx;

      //std::cout << "id " << itr->first << " m_etx" << m_etx[itr->first] << "\n";
      //std::cout << "\n";
    }
}

void
RoutingProtocol::SetPriValueMap (int32_t des_x, int32_t des_y)
{
  Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
  Vector mypos = mobility->GetPosition ();

  double Rp;
  // int nearRoadId;
  std::string nearRoadId;
  // int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  //int myRoadId = distinctionRoad (mypos.x, mypos.y);

  nearRoadId = NearRoadId (des_x, des_y);
  // std::cout << "id" << id << "が持つ(" << mypos.x << "," << mypos.y << ")"
  //           << "\n";
  // std::cout << "最も近い道路IDは" << nearRoadId << "\n";
  //最も目的地に近い道路に存在するノードのどれか一つに届く確率Rpを返す関数
  Rp = CalculateRp (nearRoadId);
  // std::cout << "Rp" << Rp << "\n";

  double Dsd; //ソースノードと目的地までの距離(sendSIGObroadcastするノード)
  double Did; //候補ノードと目的地までの距離
  double neighbor_d; //近隣ノードとの距離
  int Distination_x = des_x;
  int Distination_y = des_y;

  for (auto itr = m_etx.begin (); itr != m_etx.end (); itr++)
    { ////next                  目的地までの距離とETX値から優先度を示す値をマップに保存する
      Dsd = getDistance (mypos.x, mypos.y, Distination_x, Distination_y);
      Did = getDistance (m_pre_xpoint[itr->first], m_pre_ypoint[itr->first], Distination_x,
                         Distination_y);
      neighbor_d =
          getDistance (mypos.x, mypos.y, m_pre_xpoint[itr->first], m_pre_ypoint[itr->first]);
      int inter = 0; //初期値0 intersectionにいる場合は1に変わる
      double dif = Dsd - Did;
      if (dif < 0)
        {
          continue;
        }
      //std::cout << "id " << itr->first << " Dsd" << Dsd << " Did" << Did << "\n";

      ///交差点にいるか　いないかの場合分け
      // ************use distinctionRoad ver**********************
      // if (distinctionRoad (m_pre_xpoint[itr->first], m_pre_ypoint[itr->first]) == 0)
      //   { //roadid=0 すなわち交差点ノードならば
      //     std::cout << "候補ノードid" << itr->first << "は交差点にいます(" << m_xpoint[itr->first]
      //               << "," << m_ypoint[itr->first] << ")"
      //               << "予測位置は(" << m_pre_xpoint[itr->first] << "," << m_pre_ypoint[itr->first]
      //               << "\n";
      //     inter = 1;
      //   }

      // **************use judgeIntersection ver********************
      if (judgeIntersection (m_pre_xpoint[itr->first], m_pre_ypoint[itr->first]) == 0)
      {
        // std::cout << "候補ノードid" << itr->first << "は交差点にいます(" << m_xpoint[itr->first]
        //           << "," << m_ypoint[itr->first] << ")"
        //           << "予測位置は(" << m_pre_xpoint[itr->first] << "," << m_pre_ypoint[itr->first]
        //           << "\n";
        inter = 1;
      }

      if (inter == 1)//neighbor node = intersection node
        {
          m_pri_value[itr->first] = (Dsd - Did) / (m_etx[itr->first] * m_etx[itr->first]);
          double angle = getAngle (
              des_x, des_y, mypos.x, mypos.y, m_xpoint[itr->first],
              m_ypoint[itr->first]); //角度Bを求める 中心となる座標b_x b_y = source node  = id = id
          // std::cout << "source id" << id << "候補ノードid" << itr->first
          //           << "とのdestinationまでの角度は" << angle << "destination position(" << des_x
          //           << "," << des_y << ")"
          //           << "\n";
          double gammaAngle = angle / 90;
          gammaAngle = pow (gammaAngle, 1 / AngleGamma);
          gammaAngle = 90 * gammaAngle;

          double gammaRp = pow (Rp, 1 / RpGamma);

          if (Rp != 0 && angle > 45 && Rp != 1)
            {
              m_pri_value[itr->first] = m_pri_value[itr->first] + Grobal_InterPoint * gammaAngle / gammaRp;
              // std::cout << "total 交差点 point" << Grobal_InterPoint * gammaAngle / gammaRp;
            }

          if (neighbor_d > MaxRange)
            {
              // std::cout << "send id" << id << "neighbor id" << itr->first
              //           << "送信範囲外に出ただろう　\n";
              m_pri_value[itr->first] = 1;
            }
        }
      else // neighbor node = simple node
        {
          m_pri_value[itr->first] = (Dsd - Did) / (m_etx[itr->first] * m_etx[itr->first]);
          if (neighbor_d > MaxRange)
            {
              // std::cout << "\n\n send id" << id << "neighbor id" << itr->first
              //           << "送信範囲外に出ただろう　\n";
              // std::cout << "neighbor の予測位置は x" << m_pre_xpoint[itr->first] << "y"
              //           << m_pre_ypoint[itr->first] << "\n";
              // std::cout << "大体の正確な位置は x" << m_my_posx[itr->first] << "y"
              //           << m_my_posy[itr->first] << "\n";
              m_pri_value[itr->first] = 1;
            }
        }
      // std::cout << "id=" << itr->first << "のm_pri_value " << m_pri_value[itr->first] << "position("
      //           << m_xpoint[itr->first] << "," << m_ypoint[itr->first] << ")"
      //           << "\n";
    }
}

//目的地に最も近い道路IDを返す関数
std::string
RoutingProtocol::NearRoadId (int32_t des_x, int32_t des_y)
{
  /////////********************road id int ver
  // int nearRoadId;
  // double minDistance;
  // int count = 0;
  // for (auto itr = m_etx.begin (); itr != m_etx.end (); itr++)
  //   {
  //     //近隣ノードが位置する道路の中心座標を取得　
  //     int roadCenterX =
  //         roadCenterPointX[distinctionRoad (m_xpoint[itr->first], m_ypoint[itr->first])];
  //     int roadCenterY =
  //         roadCenterPointY[distinctionRoad (m_xpoint[itr->first], m_ypoint[itr->first])];
  //     if (distinctionRoad (roadCenterX, roadCenterY) == 0)
  //       continue;

  //     //std::cout << "id" << itr->first << "のroad idは" << distinctionRoad (roadCenterX, roadCenterY)
  //     //<< "roadCenterX" << roadCenterX << "roadCenterY" << roadCenterY << "\n";
  //     //目的地とそれぞれの道路の中心座標の距離を計算
  //     double distance = getDistance (roadCenterX, roadCenterY, des_x, des_y);
  //     //std::cout << "id" << itr->first << "distance" << distance << "\n";
  //     if (count == 0)
  //       {
  //         minDistance = distance;
  //         nearRoadId = distinctionRoad (roadCenterX, roadCenterY);
  //       }
  //     else
  //       {
  //         if (distance < minDistance)
  //           {
  //             minDistance = distance;
  //             nearRoadId = distinctionRoad (roadCenterX, roadCenterY);
  //           }
  //       }
  //     count++;
  //   }
  // return nearRoadId;

  ////////*********road id string ver****************************
  std::string nearRoadId;
  double minDistance;
  int count = 0;
  for (auto itr = m_etx.begin (); itr != m_etx.end (); itr++)
    {
      //近隣ノードが位置する道路の中心座標を取得　
      int roadCenterX =
          m_road_center_x[distinctionRoad (m_xpoint[itr->first], m_ypoint[itr->first])];
      int roadCenterY =
          m_road_center_y[distinctionRoad (m_xpoint[itr->first], m_ypoint[itr->first])];
      if (judgeIntersection (roadCenterX, roadCenterY) == 0) //intersection nodeは対象外なのでcontinue
      {
        continue;
      }

      //std::cout << "id" << itr->first << "のroad idは" << distinctionRoad (roadCenterX, roadCenterY)
      //<< "roadCenterX" << roadCenterX << "roadCenterY" << roadCenterY << "\n";
      //目的地とそれぞれの道路の中心座標の距離を計算
      double distance = getDistance (roadCenterX, roadCenterY, des_x, des_y);
      //std::cout << "id" << itr->first << "distance" << distance << "\n";
      if (count == 0)
        {
          minDistance = distance;
          nearRoadId = distinctionRoad (roadCenterX, roadCenterY);
        }
      else
        {
          if (distance < minDistance)
            {
              minDistance = distance;
              nearRoadId = distinctionRoad (roadCenterX, roadCenterY);
            }
        }
      count++;
    }
  return nearRoadId;
}

//近い道路IDを受取その道路のRpを返す
double
RoutingProtocol::CalculateRp (std::string nearRoadId)
{
  double Rp = 0;
  double missProbability = 1; //道路に存在するすべてのノードとの伝送が失敗する確率
  int count = 0;

  for (auto itr = m_rt.begin (); itr != m_rt.end (); itr++)
    {
      if (distinctionRoad (m_xpoint[itr->first], m_ypoint[itr->first]) == nearRoadId)
        {
          if (count == 0)
            {
              missProbability = 1 - m_rt[itr->first];
              // std::cout << "link を持っている node id" << itr->first << "とのrtは"
              //           << m_rt[itr->first] << "\n";
            }
          else
            {
              // std::cout << "link を持っている node id" << itr->first << "とのrtは"
              //           << m_rt[itr->first] << "\n";
              missProbability = missProbability * (1 - m_rt[itr->first]);
            }
          count++;
        }
    }

  Rp = 1 - missProbability;
  return Rp;
}

void
RoutingProtocol::SendHelloPacket (void)
{
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin ();
       j != m_socketAddresses.end (); ++j)
    {
      int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
      Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
      Vector mypos = mobility->GetPosition ();

      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      Ptr<Packet> packet = Create<Packet> ();

      int32_t acce = m_my_speed[id] - m_my_p_speed[id]; //加速度　
      // if(id == 1)
      // std::cout<<"\n-------send hello acce " <<acce << "cur speed " << m_my_speed[id] <<
      //  "past speed " << m_my_p_speed[id] <<"\n";

      HelloHeader helloHeader (id, mypos.x, mypos.y, m_my_p_posx[id], m_my_p_posy[id], acce);
      packet->AddHeader (helloHeader);

      TypeHeader tHeader (SIGOTYPE_HELLO);
      packet->AddHeader (tHeader);

      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }

      Time Jitter = Time (MicroSeconds (m_uniformRandomVariable->GetInteger (0, 50000)));

      //socket->SendTo (packet, 0, InetSocketAddress (destination, SIGO_PORT));
      Simulator::Schedule (Jitter, &RoutingProtocol::SendToHello, this, socket, packet,
                           destination);
    }
}

void
RoutingProtocol::SendToHello (Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination)
{
  // int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  // std::cout << " send id " << id << "  time  " << Simulator::Now ().GetMicroSeconds () << "\n";
  socket->SendTo (packet, 0, InetSocketAddress (destination, SIGO_PORT));
}

void
RoutingProtocol::SendToSigo (Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination,
                             int32_t hopcount, int32_t des_id)
{
  int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
  Vector mypos = mobility->GetPosition ();

  if (m_wait[des_id] == hopcount) //送信するhopcount がまだ待機中だったら
    {
      std::cout << "id " << id << " broadcast----------------------------------------------------"
                << "time" << Simulator::Now ().GetMicroSeconds () << "m_wait" << m_wait[des_id]
                << "position(" << mypos.x << "," << mypos.y << ")"
                << "\n";
      socket->SendTo (packet, 0, InetSocketAddress (destination, SIGO_PORT));
      m_wait.erase (des_id);

      if (m_finish_time[des_id] == 0) // まだ受信車両が受信してなかったら
        {
          s_send_log[m_send_check[des_id]] = 1;
          broadcount[des_id] = broadcount[des_id] + 1; // sigo recovery test 中はコメントアウト
        }
    }
  else
    {
      // std::cout << "id " << id
      //           << " ブロードキャストキャンセル----------------------------------------------------"
      //           << "m_wait" << m_wait[id] << "time" << current_time << "\n";
      m_send_check.clear (); //broadcast canselされたのでsend checkしたindexをクリア
    }

}

void
RoutingProtocol::SendSigoBroadcast (int32_t pri_value, int32_t des_id, int32_t des_x, int32_t des_y,
          int32_t hopcount, int32_t one_before_x, int32_t one_before_y)
{

  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin ();
       j != m_socketAddresses.end (); ++j)
    {
      if (hopcount > maxHop) // hop数が最大値を超えたらブレイク
        break;
      int send_node_id = m_ipv4->GetObject<Node> ()->GetId (); //broadcastするノードID
      Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
      Vector mypos = mobility->GetPosition (); //broadcastするノードの位置情報
      SetCountTimeMap (); //window sizeないの最初のhelloを受け取った時間と回数をマップに格納する関数
      SetEtxMap (); //m_rt と EtX mapをセットする
      PredictionPosition (); //予測位置を格納する
      SetPriValueMap (des_x, des_y); //優先度を決める値をセットする関数

      int32_t pri_id[6];
      pri_id[1] = 10000000; ///ダミーID
      pri_id[2] = 10000000;
      pri_id[3] = 10000000;
      pri_id[4] = 10000000;
      pri_id[5] = 10000000;

      for (int i = 1; i < 6; i++) //5回回して、大きいものから取り出して削除する
        {
          int count = 1;
          int max_id = 10000000;
          double max_value = 0;
          for (auto itr = m_pri_value.begin (); itr != m_pri_value.end (); itr++)
            {

              if (count == 1)
                {
                  max_value = m_pri_value[itr->first];
                }
              else
                {
                  if (max_value < m_pri_value[itr->first])
                    {
                      max_value = m_pri_value[itr->first];
                    }
                }
              count++;
            }

          for (auto itr = m_pri_value.begin (); itr != m_pri_value.end (); itr++)
            {

              if (m_pri_value[itr->first] == max_value)
                {
                  max_id = itr->first;
                }
            }

          m_pri_value.erase (max_id);

          switch (i)
            {
            case 1:
              pri_id[1] = max_id;
              break;
            case 2:
              pri_id[2] = max_id;
              break;
            case 3:
              pri_id[3] = max_id;
              break;
            case 4:
              pri_id[4] = max_id;
              break;
            case 5:
              pri_id[5] = max_id;
              break;
            }
        }

      //  ****************  候補ノード選択アルゴリズム *************************//
      int candidataNum = 5; // 候補ノード数　初期値は最大

      for (int n = 1; n < 6; n++) //5回回して、 条件を満たすまでまわる nは候補ノード数
        {
          double infiniteProduct = 1; // 総乗
          for (int p = 1; p <= n; p++) //pは優先度  優先度は1から回す
            {
              double rtMiss = 1 - m_rt[pri_id[p]]; // 伝送に失敗する予想確率
              infiniteProduct = infiniteProduct * rtMiss;
            }
          if (TransProbability <= (1 - infiniteProduct)) //選択アルゴリズムの条件を満たすならば
            {
              // std::cout << "infineteProduct" << infiniteProduct << "n" << n << "\n";
              candidataNum = n; //候補ノード数を変更
              break;
            }
        }

      switch (candidataNum) //候補ノード数によってダミーノードIDを加える
        {
        case 1:
          pri_id[2] = 10000000;
          pri_id[3] = 10000000;
          pri_id[4] = 10000000;
          pri_id[5] = 10000000;
          break;
        case 2:
          pri_id[3] = 10000000;
          pri_id[4] = 10000000;
          pri_id[5] = 10000000;
          break;
        case 3:
          pri_id[4] = 10000000;
          pri_id[5] = 10000000;
          break;
        case 4:
          pri_id[5] = 10000000;
          break;
        }

      if (pri_value != 0) //source node じゃなかったら
        {
          hopcount++;
        }

      s_source_id.push_back (send_node_id);
      s_source_x.push_back (mypos.x);
      s_source_y.push_back (mypos.y);
      s_time.push_back (Simulator::Now ().GetMicroSeconds ());
      s_hop.push_back (hopcount);
      s_pri_1_id.push_back (pri_id[1]);
      s_pri_2_id.push_back (pri_id[2]);
      s_pri_3_id.push_back (pri_id[3]);
      s_pri_4_id.push_back (pri_id[4]);
      s_pri_5_id.push_back (pri_id[5]);
      s_pri_1_r.push_back (m_rt[pri_id[1]]);
      s_pri_2_r.push_back (m_rt[pri_id[2]]);
      s_pri_3_r.push_back (m_rt[pri_id[3]]);
      s_pri_4_r.push_back (m_rt[pri_id[4]]);
      s_pri_5_r.push_back (m_rt[pri_id[5]]);
      s_des_id.push_back (des_id);
      s_send_log.push_back (0); //一旦0にする send関数で本当にsendしたら1 に変える
      m_send_check[des_id] = sendpacketCount;

      sendpacketCount++;

      //////////////////////// ************  交差点判定  send log 用*****************////////////////
      if (judgeIntersection (m_pre_xpoint[pri_id[1]], m_pre_ypoint[pri_id[1]]) == 0) //優先度 iのノードが交差点ノードならば
        {
          s_inter_1_id.push_back (1);
        }
      else
        {
          s_inter_1_id.push_back (0);
        }

      if (judgeIntersection (m_pre_xpoint[pri_id[2]], m_pre_ypoint[pri_id[2]]) == 0) //優先度 iのノードが交差点ノードならば
        {
          s_inter_2_id.push_back (1);
        }
      else
        {
          s_inter_2_id.push_back (0);
        }

      if (judgeIntersection (m_pre_xpoint[pri_id[3]], m_pre_ypoint[pri_id[3]]) == 0) //優先度 iのノードが交差点ノードならば
        {
          s_inter_3_id.push_back (1);
        }
      else
        {
          s_inter_3_id.push_back (0);
        }

      if (judgeIntersection (m_pre_xpoint[pri_id[4]], m_pre_ypoint[pri_id[4]]) == 0) //優先度 iのノードが交差点ノードならば
        {
          s_inter_4_id.push_back (1);
        }
      else
        {
          s_inter_4_id.push_back (0);
        }

      if (judgeIntersection (m_pre_xpoint[pri_id[5]], m_pre_ypoint[pri_id[5]]) == 0) //優先度 iのノードが交差点ノードならば
        {
          s_inter_5_id.push_back (1);
        }
      else
        {
          s_inter_5_id.push_back (0);
        }

      m_recvcount.clear ();
      m_first_recv_time.clear ();
      m_etx.clear ();
      m_pri_value.clear ();
      m_rt.clear (); //保持している予想伝送確率をクリア

      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      Ptr<Packet> packet = Create<Packet> ();


      ///////////////////////// *************recovery judgement ****************************////////////////////////
      if (pri_id[1] != 10000000) //中継候補ノードが1つ以上存在するならば
      {
        SendHeader sendHeader (des_id, des_x, des_y, send_node_id, mypos.x, mypos.y, hopcount,
                             pri_id[1], pri_id[2], pri_id[3], pri_id[4], pri_id[5]);
        packet->AddHeader (sendHeader);
        TypeHeader tHeader (SIGOTYPE_SEND);
        packet->AddHeader (tHeader);

      }else{// local optimum problem
        std::cout << "***************** local optimum problem 発生*****************\n";
        std::cout << "current node id " << send_node_id << "pos " << mypos << "\n";
        std::cout << "previous x" << one_before_x << "previous y" << one_before_y << "\n";
        std::cout << "des id " << des_id << "des x" << des_x << "des y" << des_y << "local recovery start";


        if(Grobal_recovery_protocol == 0)
        {
          // no recovery
          SendHeader sendHeader (des_id, des_x, des_y, send_node_id, mypos.x, mypos.y, hopcount,
                             pri_id[1], pri_id[2], pri_id[3], pri_id[4], pri_id[5]);
          packet->AddHeader (sendHeader);
          TypeHeader tHeader (SIGOTYPE_SEND);
          packet->AddHeader (tHeader);
        }else if(Grobal_recovery_protocol == 1)
        {
          //sigo recovery
          std::cout << "sigo recovery done \n " << std::endl;
          SendSigoRecoveryBroadcast (pri_value, des_id, des_x, des_y, mypos.x, mypos.y, hopcount, 
          one_before_x, one_before_y, one_before_x, one_before_y);
          break; //sendsigorecoverybroadcast で　送信を行うのでbreak
        }else if(Grobal_recovery_protocol == 2)
        {
          // //jbr recovery
          int32_t next_id = DecisionNextId(one_before_x, one_before_y, mypos.x, mypos.y,
          one_before_x, one_before_y, des_x, des_y);
          if(next_id == 10000) // ダミーIDならば　
          {
            std::cout << "id" << send_node_id << "はjbr recovery を breakする\n" << std::endl;
            break;
          }
          JbrHeader jbrHeader (send_node_id, mypos.x, mypos.y, next_id, mypos.x, mypos.y,
          one_before_x, one_before_y, des_id, des_x, des_y, hopcount);
          packet->AddHeader (jbrHeader);

          TypeHeader tHeader (SIGOTYPE_JBR_RECOVER);
          packet->AddHeader (tHeader);
        }else{
          //gpcr recovery
        }
      }

      

      int32_t wait_time = (pri_value * WaitT) - WaitT; //待ち時間
      std::mt19937 rand_src (Grobal_Seed); //シード値
      std::uniform_int_distribution<int> wait_Jitter (100, 500);

      wait_time = wait_time + wait_Jitter(rand_src);
      m_wait[des_id] = hopcount; //今から待機するホップカウント

      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }

      if (pri_value == 0) //初期のソースノードなら無条件にbroadcast
        {
          socket->SendTo (packet, 0, InetSocketAddress (destination, SIGO_PORT));
          std::cout << "id " << send_node_id
                    << " source node broadcast----------------------------------------------------"
                    << "time" << Simulator::Now ().GetMicroSeconds () << "\n";
        }
      else
        {
          if (pri_id[1] != 10000000) //中継候補ノードをⅠ個も持っていないノードはbrさせない
          {
            Simulator::Schedule (MicroSeconds (wait_time), &RoutingProtocol::SendToSigo, this,
                                 socket, packet, destination, hopcount, des_id);
          }else{// local optimum problem or neighbor node 0
                // recovery protocolの場合分け
            if (Grobal_recovery_protocol != 0)
            {
              Simulator::Schedule (MicroSeconds (wait_time), &RoutingProtocol::SendToSigo, this,
                                 socket, packet, destination, hopcount, des_id);
            }
          }
        }
    }
} 

void
RoutingProtocol::FirstSendSigoBroadcast (int32_t pri_value, int32_t des_id, int32_t des_x, int32_t des_y,
                                    int32_t hopcount)
{

  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin ();
       j != m_socketAddresses.end (); ++j)
    {
      if (hopcount > maxHop) // hop数が最大値を超えたらブレイク
        break;
      int send_node_id = m_ipv4->GetObject<Node> ()->GetId (); //broadcastするノードID
      Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
      Vector mypos = mobility->GetPosition (); //broadcastするノードの位置情報
      SetCountTimeMap (); //window sizeないの最初のhelloを受け取った時間と回数をマップに格納する関数
      SetEtxMap (); //m_rt と EtX mapをセットする
      PredictionPosition (); //予測位置を格納する
      SetPriValueMap (des_x, des_y); //優先度を決める値をセットする関数

      int32_t pri_id[6];
      pri_id[1] = 10000000; ///ダミーID
      pri_id[2] = 10000000;
      pri_id[3] = 10000000;
      pri_id[4] = 10000000;
      pri_id[5] = 10000000;

      for (int i = 1; i < 6; i++) //5回回して、大きいものから取り出して削除する
        {
          int count = 1;
          int max_id = 10000000;
          double max_value = 0;
          for (auto itr = m_pri_value.begin (); itr != m_pri_value.end (); itr++)
            {

              if (count == 1)
                {
                  max_value = m_pri_value[itr->first];
                }
              else
                {
                  if (max_value < m_pri_value[itr->first])
                    {
                      max_value = m_pri_value[itr->first];
                    }
                }
              count++;
            }

          for (auto itr = m_pri_value.begin (); itr != m_pri_value.end (); itr++)
            {

              if (m_pri_value[itr->first] == max_value)
                {
                  max_id = itr->first;
                }
            }

          m_pri_value.erase (max_id);

          switch (i)
            {
            case 1:
              pri_id[1] = max_id;
              break;
            case 2:
              pri_id[2] = max_id;
              break;
            case 3:
              pri_id[3] = max_id;
              break;
            case 4:
              pri_id[4] = max_id;
              break;
            case 5:
              pri_id[5] = max_id;
              break;
            }
        }

      // 候補ノード選択アルゴリズム
      int candidataNum = 5; // 候補ノード数　初期値は最大

      for (int n = 1; n < 6; n++) //5回回して、 条件を満たすまでまわる nは候補ノード数
        {
          double infiniteProduct = 1; // 総乗
          for (int p = 1; p <= n; p++) //pは優先度  優先度は1から回す
            {
              double rtMiss = 1 - m_rt[pri_id[p]]; // 伝送に失敗する予想確率
              infiniteProduct = infiniteProduct * rtMiss;
            }
          if (TransProbability <= (1 - infiniteProduct)) //選択アルゴリズムの条件を満たすならば
            {
              std::cout << "infineteProduct" << infiniteProduct << "n" << n << "\n";
              candidataNum = n; //候補ノード数を変更
              break;
            }
        }

      //std::cout << "候補ノード数は" << candidataNum << "\n";
      switch (candidataNum) //候補ノード数によってダミーノードIDを加える
        {
        case 1:
          pri_id[2] = 10000000;
          pri_id[3] = 10000000;
          pri_id[4] = 10000000;
          pri_id[5] = 10000000;
          break;
        case 2:
          pri_id[3] = 10000000;
          pri_id[4] = 10000000;
          pri_id[5] = 10000000;
          break;
        case 3:
          pri_id[4] = 10000000;
          pri_id[5] = 10000000;
          break;
        case 4:
          pri_id[5] = 10000000;
          break;
        }

      for (int i = 1; i < 6; i++)
        {
          if (pri_id[i] != 10000000)
            {
              std::cout << "優先度" << i << "の node id = " << pri_id[i] << "予想伝送確率"
                        << m_rt[pri_id[i]] << "\n";
            }
        }
      if (pri_value != 0) //source node じゃなかったら
        {
          hopcount++;
        }

      s_source_id.push_back (send_node_id);
      std::cout << "s_source_id push back  send_node_id = " << send_node_id << "\n";
      s_source_x.push_back (mypos.x);
      s_source_y.push_back (mypos.y);
      s_time.push_back (Simulator::Now ().GetMicroSeconds ());
      s_hop.push_back (hopcount);
      s_pri_1_id.push_back (pri_id[1]);
      s_pri_2_id.push_back (pri_id[2]);
      s_pri_3_id.push_back (pri_id[3]);
      s_pri_4_id.push_back (pri_id[4]);
      s_pri_5_id.push_back (pri_id[5]);
      s_pri_1_r.push_back (m_rt[pri_id[1]]);
      s_pri_2_r.push_back (m_rt[pri_id[2]]);
      s_pri_3_r.push_back (m_rt[pri_id[3]]);
      s_pri_4_r.push_back (m_rt[pri_id[4]]);
      s_pri_5_r.push_back (m_rt[pri_id[5]]);
      s_des_id.push_back (des_id);
      s_send_log.push_back (0); //一旦0にする send関数で本当にsendしたら1 に変える
      m_send_check[des_id] = sendpacketCount;

      sendpacketCount++;
      ////////////////////////交差点判定
      if (judgeIntersection (m_xpoint[pri_id[1]], m_ypoint[pri_id[1]]) == 0) //優先度 iのノードが交差点ノードならば
        {
          s_inter_1_id.push_back (1);
        }
      else
        {
          s_inter_1_id.push_back (0);
        }

      if (judgeIntersection (m_xpoint[pri_id[2]], m_ypoint[pri_id[2]]) == 0) //優先度 iのノードが交差点ノードならば
        {
          s_inter_2_id.push_back (1);
        }
      else
        {
          s_inter_2_id.push_back (0);
        }

      if (judgeIntersection (m_xpoint[pri_id[3]], m_ypoint[pri_id[3]]) == 0) //優先度 iのノードが交差点ノードならば
        {
          s_inter_3_id.push_back (1);
        }
      else
        {
          s_inter_3_id.push_back (0);
        }

      if (judgeIntersection (m_xpoint[pri_id[4]], m_ypoint[pri_id[4]]) == 0) //優先度 iのノードが交差点ノードならば
        {
          s_inter_4_id.push_back (1);
        }
      else
        {
          s_inter_4_id.push_back (0);
        }

      if (judgeIntersection (m_xpoint[pri_id[5]], m_ypoint[pri_id[5]]) == 0) //優先度 iのノードが交差点ノードならば
        {
          s_inter_5_id.push_back (1);
        }
      else
        {
          s_inter_5_id.push_back (0);
        }

      m_recvcount.clear ();
      m_first_recv_time.clear ();
      m_etx.clear ();
      m_pri_value.clear ();
      m_rt.clear (); //保持している予想伝送確率をクリア

      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      Ptr<Packet> packet = Create<Packet> ();

      SendHeader sendHeader (des_id, des_x, des_y, send_node_id, mypos.x, mypos.y, hopcount,
                             pri_id[1], pri_id[2], pri_id[3], pri_id[4], pri_id[5]);

      packet->AddHeader (sendHeader);

      TypeHeader tHeader (SIGOTYPE_SEND);
      packet->AddHeader (tHeader);

      int32_t wait_time = (pri_value * WaitT) - WaitT; //待ち時間
      std::mt19937 rand_src (Grobal_Seed); //シード値
      std::uniform_int_distribution<int> wait_Jitter (100, 500);

      wait_time = wait_time + wait_Jitter(rand_src);
      m_wait[des_id] = hopcount; //今から待機するホップカウント

      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }

      if (pri_value == 0) //初期のソースノードなら無条件にbroadcast
        {
          socket->SendTo (packet, 0, InetSocketAddress (destination, SIGO_PORT));
          std::cout << "id " << send_node_id
                    << " source node broadcast----------------------------------------------------"
                    << "time" << Simulator::Now ().GetMicroSeconds () << "\n";
        }
      else
        {
          if (pri_id[1] != 10000000) //中継候補ノードをⅠ個も持っていないノードはbrさせない
          {
            Simulator::Schedule (MicroSeconds (wait_time), &RoutingProtocol::SendToSigo, this,
                                 socket, packet, destination, hopcount, des_id);
          }
        }
    }
} 


// ***************recovery sigo ******************////

void
RoutingProtocol::SendSigoRecoveryBroadcast(int32_t pri_value, int32_t des_id, int32_t des_x, int32_t des_y,
    int32_t local_source_x, int32_t local_source_y,int32_t hopcount, 
    int32_t one_before_x, int32_t one_before_y, int32_t previous_x, int32_t previous_y)
{
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin ();
      j != m_socketAddresses.end (); ++j)
  {
    if (hopcount > maxHop) // hop数が最大値を超えたらブレイク
      break;

    if (pri_value != 0) //source node じゃなかったら
    {
      hopcount++;
    }
    
    std::cout << "call send sigo recovery broadcast"<<std::endl;

    int send_node_id = m_ipv4->GetObject<Node> ()->GetId (); //broadcastするノードID
    Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
    Vector mypos = mobility->GetPosition (); //broadcastするノードの位置情報

    int candidate_node_id[NumCandidateNodes + 1];
    // candidate node id が value  配列番号は 優先度 配列番号 0　は使用しない
    DecisionSigoRecoveryCandidate(one_before_x, one_before_y, local_source_x, local_source_y,
    previous_x, previous_y, des_x, des_y, candidate_node_id);

    Ptr<Socket> socket = j->first;
    Ipv4InterfaceAddress iface = j->second;
    Ptr<Packet> packet = Create<Packet> ();

    RecoverHeader recoverHeader (des_id, des_x, des_y, send_node_id, mypos.x, mypos.y, hopcount,
      candidate_node_id[1], candidate_node_id[2], candidate_node_id[3], candidate_node_id[4], 
      candidate_node_id[5], local_source_x, local_source_y, previous_x, previous_y);
    packet->AddHeader (recoverHeader);
    TypeHeader tHeader (SIGOTYPE_RECOVER);
    packet->AddHeader (tHeader);

    int32_t wait_time = (pri_value * WaitT) - WaitT; //待ち時間
    std::mt19937 rand_src (Grobal_Seed); //シード値
    std::uniform_int_distribution<int> wait_Jitter (100, 500);

    wait_time = wait_time + wait_Jitter(rand_src);
    m_wait[des_id] = hopcount; //今から待機するホップカウント

    s_source_id.push_back (send_node_id);
    s_source_x.push_back (mypos.x);
    s_source_y.push_back (mypos.y);
    s_time.push_back (Simulator::Now ().GetMicroSeconds ());
    s_hop.push_back (hopcount);
    s_pri_1_id.push_back (candidate_node_id[1]);
    s_pri_2_id.push_back (candidate_node_id[2]);
    s_pri_3_id.push_back (candidate_node_id[3]);
    s_pri_4_id.push_back (candidate_node_id[4]);
    s_pri_5_id.push_back (candidate_node_id[5]);
    s_pri_1_r.push_back (m_rt[candidate_node_id[1]]);
    s_pri_2_r.push_back (m_rt[candidate_node_id[2]]);
    s_pri_3_r.push_back (m_rt[candidate_node_id[3]]);
    s_pri_4_r.push_back (m_rt[candidate_node_id[4]]);
    s_pri_5_r.push_back (m_rt[candidate_node_id[5]]);
    s_des_id.push_back (des_id);
    s_send_log.push_back (0); //一旦0にする send関数で本当にsendしたら1 に変える
    m_send_check[des_id] = sendpacketCount;
    s_inter_1_id.push_back (0);
    s_inter_2_id.push_back (0);
    s_inter_3_id.push_back (0);
    s_inter_4_id.push_back (0);
    s_inter_5_id.push_back (0);

    sendpacketCount++;

    // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
    Ipv4Address destination;
    if (iface.GetMask () == Ipv4Mask::GetOnes ())
    {
      destination = Ipv4Address ("255.255.255.255");
    }
    else
    {
      destination = iface.GetBroadcast ();
    }

    if (candidate_node_id[1] != 10000000) //中継候補ノードをⅠ個も持っていないノードはbrさせない
    {
      Simulator::Schedule (MicroSeconds (wait_time), &RoutingProtocol::SendToSigo, this,
                            socket, packet, destination, hopcount, des_id);
    }
  }
}


void 
RoutingProtocol::DecisionSigoRecoveryCandidate (int32_t one_before_x, int32_t one_before_y, 
int32_t local_source_x, int32_t local_source_y, int32_t previous_x, 
int32_t previous_y, int32_t des_x, int32_t des_y, int32_t candidate_node_id[NumCandidateNodes + 1])
{
  for(int i = 1; i < NumCandidateNodes + 1; i++)
  {
    candidate_node_id[i] = 10000000; ///ダミーID で初期化
  }

  SetCountTimeMap (); //window sizeないの最初のhelloを受け取った時間と回数をマップに格納する関数
  SetEtxMap (); //m_rt と EtX mapをセットする
  PredictionPosition (); //予測位置を格納する
  SetRecoverPriValue (one_before_x, one_before_y, local_source_x, local_source_y,
  previous_x, previous_y, des_x, des_y); 
  // 予測位置とprediction positionをつかって recovery privalue を求める

  // m_recovery_pri_valueが大きい順にcandidate node idに格納
  for (int i = 1; i < NumCandidateNodes + 1; i++) //5回回して、大きいものから取り出して削除する
  {
    int count = 1;
    int max_id = 10000000;
    double max_value = 0;

    for (auto itr = m_recovery_pri_value.begin (); itr != m_recovery_pri_value.end (); itr++)
      {

        if (count == 1)
          {
            max_value = m_recovery_pri_value[itr->first];
          }
        else
          {
            if (max_value < m_recovery_pri_value[itr->first])
              {
                max_value = m_recovery_pri_value[itr->first];
              }
          }
        count++;
      }

    for (auto itr = m_recovery_pri_value.begin (); itr != m_recovery_pri_value.end (); itr++)
      {

        if (m_recovery_pri_value[itr->first] == max_value)
          {
            max_id = itr->first;
          }
      }
    m_recovery_pri_value.erase (max_id);

    switch (i)
      {
      case 1:
        candidate_node_id[1] = max_id;
        break;
      case 2:
        candidate_node_id[2] = max_id;
        break;
      case 3:
        candidate_node_id[3] = max_id;
        break;
      case 4:
        candidate_node_id[4] = max_id;
        break;
      case 5:
        candidate_node_id[5] = max_id;
        break;
      }
  }

  m_recvcount.clear ();
  m_first_recv_time.clear ();
  m_etx.clear ();
  m_pri_value.clear ();
  m_rt.clear (); //保持している予想伝送確率をクリア
  m_recovery_pri_value.clear();

}

void
RoutingProtocol::SetRecoverPriValue(int32_t one_before_x, int32_t one_before_y, 
  int32_t local_source_x, int32_t local_source_y, int32_t previous_x, int32_t previous_y, 
  int32_t des_x, int32_t des_y)
{
  Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
  Vector mypos = mobility->GetPosition (); //broadcastするノードの位置情報
  std::string current_road_segment = distinctionRoad(mypos.x, mypos.y);

  for (auto itr = m_etx.begin (); itr != m_etx.end (); itr++)
  {
    double minangle;
    double sdangle = getAngle (des_x, des_y, local_source_x, local_source_y,
    previous_x, previous_y);
    double snangle = getAngle (m_pre_xpoint[itr->first], m_pre_ypoint[itr->first], local_source_x, 
    local_source_y, previous_x, previous_y);
    int sdangle_direction = RotationDirection (des_x, des_y, local_source_x, 
    local_source_y, previous_x, previous_y);
    int snangle_direction = RotationDirection (m_pre_xpoint[itr->first], m_pre_ypoint[itr->first], 
    local_source_x, local_source_y, previous_x, previous_y);

    //jbr 条件 1
    double mndis = getDistance (mypos.x, mypos.y, 
    m_pre_xpoint[itr->first], m_pre_ypoint[itr->first]); //current to potential 
    double cldis = getDistance (one_before_x, one_before_y, 
    mypos.x, mypos.y); // current to one_before
    double nldis = getDistance (m_pre_xpoint[itr->first], m_pre_ypoint[itr->first], 
    one_before_x, one_before_y); // onebefore to potential

    if(nldis > cldis && nldis > mndis) //jbr  potential nodeの条件
    {
        //符号判定 同じ符号でなければ　角度の回転方向が違えば
      if (signbit(sdangle_direction) != signbit(snangle_direction))
      {
        // std::cout << "\n\n id" << itr->first << "角度修正 snagle before" << snangle;
        snangle = 360 - snangle;
        // std::cout << "after" << snangle << std::endl;
      }

      minangle = sdangle - snangle;

      //minangle は絶対値の差
      if (minangle < 0)
      {
        minangle = - minangle;
      }
      

      if(judgeIntersection(mypos.x, mypos.y) == 0) //current nodeがcoordinator
      {
        // neighbor nodeの　優先度式は　統一
        m_recovery_pri_value[itr->first] = (360 - minangle) / (m_etx[itr->first] * m_etx[itr->first]);
      }else{
        // 同一road segment どうかの場合分け
        std::string neighbor_road_segment = distinctionRoad(m_pre_xpoint[itr->first], m_pre_ypoint[itr->first]);
        if(judgeIntersection(m_pre_xpoint[itr->first], m_pre_ypoint[itr->first]) == 0 || 
          neighbor_road_segment == current_road_segment)
          {
            // neighbr node が　交差点ノード  or  current node と　neighbor node の道路が同じならば
            m_recovery_pri_value[itr->first] = (360 - minangle) / (m_etx[itr->first] * m_etx[itr->first]);
            m_recovery_pri_value[itr->first] = m_recovery_pri_value[itr->first] + mndis;
          }else{
            m_recovery_pri_value[itr->first] = (360 - minangle) / (m_etx[itr->first] * m_etx[itr->first]);
          }
        
      }
    }
  }
}



void
RoutingProtocol::RecvSigo (Ptr<Socket> socket)
{
  int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
  Vector mypos = mobility->GetPosition ();

  Address sourceAddress;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddress);
  TypeHeader tHeader (SIGOTYPE_HELLO);
  packet->RemoveHeader (tHeader);

  if (!tHeader.IsValid ())
    {
      NS_LOG_DEBUG ("Senko protocol message " << packet->GetUid ()
                                              << " with unknown type received: " << tHeader.Get ()
                                              << ". Drop");
      return; // drop
    }
  switch (tHeader.Get ())
    {
      case SIGOTYPE_HELLO: { //hello message を受け取った場合

        HelloHeader helloheader;
        packet->RemoveHeader (helloheader); //近隣ノードからのhello packet
        int32_t recv_hello_id = helloheader.GetNodeId (); //NOde ID
        int32_t recv_hello_posx = helloheader.GetPosX (); //Node xposition
        int32_t recv_hello_posy = helloheader.GetPosY (); //Node yposition
        int32_t recv_hello_p_posx = helloheader.GetPPosX (); //Node xposition
        int32_t recv_hello_p_posy = helloheader.GetPPosY (); //Node ypositionf
        int32_t recv_hello_acce = helloheader.GetAcce ();
        int32_t recv_hello_time = Simulator::Now ().GetMicroSeconds (); //

        SaveXpoint (recv_hello_id, recv_hello_posx, recv_hello_p_posx);
        SaveYpoint (recv_hello_id, recv_hello_posy, recv_hello_p_posy);
        setVector (recv_hello_id, recv_hello_posx, recv_hello_posy, recv_hello_p_posx,
                   recv_hello_p_posy, recv_hello_acce);
        SaveRecvTime (recv_hello_id, recv_hello_time);
        // SaveRelation (recv_hello_id, recv_hello_posx, recv_hello_posy);
        break; //breakがないとエラー起きる
      }
      case SIGOTYPE_SEND: {

        SendHeader sendheader;
        packet->RemoveHeader (sendheader);

        int32_t des_id = sendheader.GetDesId ();
        int32_t des_x = sendheader.GetPosX ();
        int32_t des_y = sendheader.GetPosY ();
        int32_t send_id = sendheader.GetSendId ();
        int32_t send_x = sendheader.GetSendPosX ();
        int32_t send_y = sendheader.GetSendPosY ();
        int32_t hopcount = sendheader.GetHopcount ();
        int32_t pri_id[] = {sendheader.GetId1 (), sendheader.GetId2 (), sendheader.GetId3 (),
                            sendheader.GetId4 (), sendheader.GetId5 ()};

        double distance = getDistance (mypos.x, mypos.y, send_x, send_y);
        if (distance > maxLenge)
          {
            maxLenge = distance;
          }

        if (des_id == id) //宛先が自分だったら
          {

            std::cout << "time" << Simulator::Now ().GetMicroSeconds () << "  id" << id
                      << "受信しましたよ　成功しました-------------\n";
            if (m_finish_time[des_id] == 0)
              {
                m_finish_time[des_id] = Simulator::Now ().GetMicroSeconds ();

                p_source_x.push_back (send_x);
                p_source_y.push_back (send_y);
                p_recv_x.push_back (mypos.x);
                p_recv_y.push_back (mypos.y);
                p_recv_time.push_back (Simulator::Now ().GetMicroSeconds ());
                p_recv_priority.push_back (id); //dummy 0
                p_hopcount.push_back (hopcount);
                p_recv_id.push_back (id);
                p_source_id.push_back (send_id);
                p_destination_id.push_back (des_id);
                p_destination_x.push_back (des_x);
                p_destination_y.push_back (des_y);
                p_pri_1.push_back (pri_id[0]);
                p_pri_2.push_back (pri_id[1]);
                p_pri_3.push_back (pri_id[2]);
                p_pri_4.push_back (pri_id[3]);
                p_pri_5.push_back (pri_id[4]);
                p_recovery.push_back (0);
                packetCount++;
              }
            break;
          }

        if (m_wait[des_id] != 0) //待ち状態ならば
          {
            if (m_wait[des_id] >= hopcount)
              { //待機中のホップカウントより大きいホップカウントを受け取ったなら
                m_wait.erase (des_id);
              }

            for (int i = 0; i < 5; i++)
              {
                if (id == pri_id[i]) //packetに自分のIDが含まれているか
                  {
                    std::cout << "\n--------------------------------------------------------\n";
                    std::cout << "関係ある normal packet recv id" << id << "time------------------------------\n"
                              << Simulator::Now ().GetMicroSeconds ();
                    if (m_finish_time[des_id] == 0)
                      {
                        p_source_x.push_back (send_x);
                        p_source_y.push_back (send_y);
                        p_recv_x.push_back (mypos.x);
                        p_recv_y.push_back (mypos.y);
                        p_recv_time.push_back (Simulator::Now ().GetMicroSeconds ());
                        p_recv_priority.push_back (i + 1);
                        p_hopcount.push_back (hopcount);
                        p_recv_id.push_back (id);
                        p_source_id.push_back (send_id);
                        p_destination_id.push_back (des_id);
                        p_destination_x.push_back (des_x);
                        p_destination_y.push_back (des_y);
                        p_pri_1.push_back (pri_id[0]);
                        p_pri_2.push_back (pri_id[1]);
                        p_pri_3.push_back (pri_id[2]);
                        p_pri_4.push_back (pri_id[3]);
                        p_pri_5.push_back (pri_id[4]);
                        p_recovery.push_back (0);
                        packetCount++;
                      }
                    SendSigoBroadcast (i + 1, des_id, des_x, des_y, hopcount, send_x, send_y);
                  }
                else //含まれていないか
                  {
                    //m_wait.erase (des_id); //マップの初期化をして　broadcastを止める
                  }
              }
          }
        else //待ち状態じゃないならば
          {
            for (int i = 0; i < 5; i++)
              {
                if (id == pri_id[i]) //packetに自分のIDが含まれているか
                  {
                    std::cout << "\n--------------------------------------------------------\n";
                    std::cout << "関係ある normal packet recv id" << id << "time------------------------------"
                              << Simulator::Now ().GetMicroSeconds () << "\n";
                    if (m_finish_time[des_id] == 0) //destinatino がまだパケットを受信していなかったら
                      {

                        p_source_x.push_back (send_x);
                        p_source_y.push_back (send_y);
                        p_recv_x.push_back (mypos.x);
                        p_recv_y.push_back (mypos.y);
                        p_recv_time.push_back (Simulator::Now ().GetMicroSeconds ());
                        p_recv_priority.push_back (i + 1);
                        p_hopcount.push_back (hopcount);
                        p_recv_id.push_back (id);
                        p_source_id.push_back (send_id);
                        p_destination_id.push_back (des_id);
                        p_destination_x.push_back (des_x);
                        p_destination_y.push_back (des_y);
                        p_pri_1.push_back (pri_id[0]);
                        p_pri_2.push_back (pri_id[1]);
                        p_pri_3.push_back (pri_id[2]);
                        p_pri_4.push_back (pri_id[3]);
                        p_pri_5.push_back (pri_id[4]);
                        p_recovery.push_back (0);
                        packetCount++;
                      }
                    SendSigoBroadcast (i + 1, des_id, des_x, des_y, hopcount, send_x, send_y);
                  }
                else //含まれていないか
                  {
                  }
              }
          }

        break;
      }case SIGOTYPE_JBR_RECOVER:
      {

        JbrHeader jbrheader;
        packet->RemoveHeader (jbrheader);
        int32_t send_id = jbrheader.GetDesId ();
        int32_t send_x = jbrheader.GetSendX ();
        int32_t send_y = jbrheader.GetSendY ();
        int32_t local_source_x = jbrheader.GetLocalSourceX ();
        int32_t local_source_y = jbrheader.GetLocalSourceY ();
        int32_t previous_x = jbrheader.GetPreviousX (); 
        int32_t previous_y = jbrheader.GetPreviousY (); 
        int32_t next_id = jbrheader.GetNextId ();
        int32_t des_id = jbrheader.GetDesId (); 
        int32_t des_x = jbrheader.GetDesX ();
        int32_t des_y = jbrheader.GetDesY (); 
        int32_t hop = jbrheader.GetHop ();

        if (m_wait[des_id] != 0) //待ち状態ならば
        {
          if (m_wait[des_id] >= hop)
            { //待機中のホップカウントより大きいホップカウントを受け取ったなら
              std::cout << "------recovery packet recv id " << id << "sigo broadacast cancel\n";
              m_wait.erase (des_id);
            }
        }        

        if (next_id == id) //packet の next hopが自分だったら　
        {
          if (m_finish_time[des_id] == 0) //destinatino がまだパケットを受信していなかったら
          {
            p_source_x.push_back (send_x);
            p_source_y.push_back (send_y);
            p_recv_x.push_back (mypos.x);
            p_recv_y.push_back (mypos.y);
            p_recv_time.push_back (Simulator::Now ().GetMicroSeconds ());
            p_recv_priority.push_back (1);
            p_hopcount.push_back (hop);
            p_recv_id.push_back (id);
            p_source_id.push_back (send_id);
            p_destination_id.push_back (des_id);
            p_destination_x.push_back (des_x);
            p_destination_y.push_back (des_y);
            p_pri_1.push_back (next_id);
            p_pri_2.push_back (next_id);
            p_pri_3.push_back (next_id);
            p_pri_4.push_back (next_id);
            p_pri_5.push_back (next_id);
            p_recovery.push_back (1);
          }
          std::cout << "recovery packet receive------------- time " 
          << Simulator::Now ().GetMicroSeconds () << "id " << id << "\n";

          int32_t local_source_distance = getDistance (local_source_x, local_source_y, des_x, des_y);
          int32_t current_distance = getDistance (mypos.x, mypos.y, des_x, des_y);

          if (local_source_distance > current_distance) //local optimum revovery
          {
            std::cout << "\nlocal optimum's recovery successful!  node id " << id << "\n";
            std::cout << "local source node x y " << local_source_x << " , "<< local_source_y << 
            "current distance to destination" << current_distance << "\n";
            SendSigoBroadcast(0, des_id, des_x, des_y, hop, send_x, send_y);// もとのルーティングに戻る　
          }
          else { //no recovery
            if (maxHop < hop)
            {
              std::cout << "\n*************reach max hop************* \n";
              break;
            }
            std::cout << "local optimum's recovery continu receive id " << id << "\n";
            SendJbrUnicast(send_x, send_y, local_source_x, local_source_y, previous_x, previous_y,
            des_id, des_x, des_y, hop); // jbr unicast 
          }
        }
        break;
      }case SIGOTYPE_RECOVER:
      {
        RecoverHeader recoverheader;
        packet->RemoveHeader (recoverheader);

        int32_t des_id = recoverheader.GetDesId ();
        int32_t des_x = recoverheader.GetPosX ();
        int32_t des_y = recoverheader.GetPosY ();
        int32_t send_id = recoverheader.GetSendId ();
        int32_t send_x = recoverheader.GetSendPosX ();
        int32_t send_y = recoverheader.GetSendPosY ();
        int32_t hopcount = recoverheader.GetHopcount ();
        int32_t pri_id[] = {recoverheader.GetId1 (), recoverheader.GetId2 (), recoverheader.GetId3 (),
                            recoverheader.GetId4 (), recoverheader.GetId5 ()};
        int32_t local_source_x = recoverheader.GetLocalSourceX ();
        int32_t local_source_y = recoverheader.GetLocalSourceY ();
        int32_t previous_x = recoverheader.GetPreviousX (); 
        int32_t previous_y = recoverheader.GetPreviousY ();

        int32_t local_source_distance = getDistance (local_source_x, local_source_y, des_x, des_y);
        int32_t current_distance = getDistance (mypos.x, mypos.y, des_x, des_y);

        int recover_judge = 0; // 0 = recover continue    1 =  recover successful

        if (local_source_distance > current_distance) //local optimum revovery
        {
          recover_judge = 1; // recover successful
        }
        

        double distance = getDistance (mypos.x, mypos.y, send_x, send_y);
        if (distance > maxLenge)
          {
            maxLenge = distance;
          }

        if (des_id == id) //宛先が自分だったら
          {

            std::cout << "time" << Simulator::Now ().GetMicroSeconds () << "  id" << id
                      << "受信しましたよ　成功しました  recover packet経由-------------\n";
            if (m_finish_time[des_id] == 0)
              {
                m_finish_time[des_id] = Simulator::Now ().GetMicroSeconds ();

                p_source_x.push_back (send_x);
                p_source_y.push_back (send_y);
                p_recv_x.push_back (mypos.x);
                p_recv_y.push_back (mypos.y);
                p_recv_time.push_back (Simulator::Now ().GetMicroSeconds ());
                p_recv_priority.push_back (id); //dummy 0
                p_hopcount.push_back (hopcount);
                p_recv_id.push_back (id);
                p_source_id.push_back (send_id);
                p_destination_id.push_back (des_id);
                p_destination_x.push_back (des_x);
                p_destination_y.push_back (des_y);
                p_pri_1.push_back (pri_id[0]);
                p_pri_2.push_back (pri_id[1]);
                p_pri_3.push_back (pri_id[2]);
                p_pri_4.push_back (pri_id[3]);
                p_pri_5.push_back (pri_id[4]);
                p_recovery.push_back (1);
                packetCount++;
              }
            break;
          }

        if (m_wait[des_id] != 0) //待ち状態ならば
          {
            if (m_wait[des_id] >= hopcount)
              { //待機中のホップカウントより大きいホップカウントを受け取ったなら
                m_wait.erase (des_id);
              }

            for (int i = 0; i < 5; i++)
              {
                if (id == pri_id[i]) //packetに自分のIDが含まれているか
                  {
                    // //std::cout << "\n--------------------------------------------------------\n";
                    std::cout << "関係ある recover packet recv id" << id << "time-----------\n"
                              << Simulator::Now ().GetMicroSeconds ();
                    if (m_finish_time[des_id] == 0)
                      {
                        p_source_x.push_back (send_x);
                        p_source_y.push_back (send_y);
                        p_recv_x.push_back (mypos.x);
                        p_recv_y.push_back (mypos.y);
                        p_recv_time.push_back (Simulator::Now ().GetMicroSeconds ());
                        p_recv_priority.push_back (i + 1);
                        p_hopcount.push_back (hopcount);
                        p_recv_id.push_back (id);
                        p_source_id.push_back (send_id);
                        p_destination_id.push_back (des_id);
                        p_destination_x.push_back (des_x);
                        p_destination_y.push_back (des_y);
                        p_pri_1.push_back (pri_id[0]);
                        p_pri_2.push_back (pri_id[1]);
                        p_pri_3.push_back (pri_id[2]);
                        p_pri_4.push_back (pri_id[3]);
                        p_pri_5.push_back (pri_id[4]);
                        p_recovery.push_back (1);
                        packetCount++;
                      }
                      if(recover_judge == 0)
                      {
                        SendSigoRecoveryBroadcast (i + 1, des_id, des_x, des_y, local_source_x, local_source_y, 
                        hopcount, send_x, send_y, previous_x, previous_y);
                        std::cout << "-- local optimum recovery continue id = " << id << "pos " << mypos << std::endl; 
                      }else{
                        std::cout << "-- local optimum recovery successful   id = " << id << "pos " << mypos << std::endl;
                        SendSigoBroadcast (i + 1, des_id, des_x, des_y, hopcount, send_x, send_y);
                      }
                  }
                else //含まれていないか
                  {
                    //m_wait.erase (des_id); //マップの初期化をして　broadcastを止める
                  }
              }
          }
        else //待ち状態じゃないならば
          {
            for (int i = 0; i < 5; i++)
              {
                if (id == pri_id[i]) //packetに自分のIDが含まれているか
                  {
                    //std::cout << "\n--------------------------------------------------------\n";
                    std::cout << "関係ある recovery packet recv id" << id << "time----------------------"
                              << Simulator::Now ().GetMicroSeconds () << "\n";
                    if (m_finish_time[des_id] == 0) //destinatino がまだパケットを受信していなかったら
                      {

                        p_source_x.push_back (send_x);
                        p_source_y.push_back (send_y);
                        p_recv_x.push_back (mypos.x);
                        p_recv_y.push_back (mypos.y);
                        p_recv_time.push_back (Simulator::Now ().GetMicroSeconds ());
                        p_recv_priority.push_back (i + 1);
                        p_hopcount.push_back (hopcount);
                        p_recv_id.push_back (id);
                        p_source_id.push_back (send_id);
                        p_destination_id.push_back (des_id);
                        p_destination_x.push_back (des_x);
                        p_destination_y.push_back (des_y);
                        p_pri_1.push_back (pri_id[0]);
                        p_pri_2.push_back (pri_id[1]);
                        p_pri_3.push_back (pri_id[2]);
                        p_pri_4.push_back (pri_id[3]);
                        p_pri_5.push_back (pri_id[4]);
                        p_recovery.push_back (1);
                        packetCount++;
                      }
                    if(recover_judge == 0)
                    {
                      SendSigoRecoveryBroadcast (i + 1, des_id, des_x, des_y, local_source_x, local_source_y, 
                      hopcount, send_x, send_y, previous_x, previous_y);
                      std::cout << "local optimum recovery continue id = " << id << "pos " << mypos << std::endl; 
                    }else{
                      std::cout << "local optimum recovery successful   id = " << id << "pos " << mypos << std::endl;
                      SendSigoBroadcast (i + 1, des_id, des_x, des_y, hopcount, send_x, send_y);
                    }
                  }
                else //含まれていないか
                  {
                  }
              }
          }
        break;
      }
    }
}

void
RoutingProtocol::SaveXpoint (int32_t map_id, int32_t map_xpoint, int32_t map_p_xpoint)
{
  m_xpoint[map_id] = map_xpoint;
  m_p_xpoint[map_id] = map_p_xpoint; //過去のx座標
}

void
RoutingProtocol::SaveYpoint (int32_t map_id, int32_t map_ypoint, int32_t map_p_ypoint)
{
  m_ypoint[map_id] = map_ypoint;
  m_p_ypoint[map_id] = map_p_ypoint; //過去のy座標
}
//速度　加速度 方向(radian cos sin の計算がしやすいため　) を保存する
void
RoutingProtocol::setVector (int hello_id, double x, double y, double xp, double yp, int acce)
{
  m_acce[hello_id] = acce; //加速度を保存　
  double distance = getDistance (x, y, xp, yp); //1secondの位置の移動なのでこれがm/sの秒速になる
  m_speed[hello_id] = distance; // 速度を保存

  x = x - xp;
  y = y - yp;
  double radian = std::atan2 (y, x);

  m_radian[hello_id] = radian;
}

void
RoutingProtocol::PredictionPosition (void) //近隣ノードの予測位置を保存する
{
  for (auto itr = m_speed.begin (); itr != m_speed.end (); itr++) //近隣テーブルをループ
    {

      double diftime = Simulator::Now ().GetMicroSeconds () - m_last_recv_time[itr->first];
      diftime = diftime / 1000000; //secondに変換
      double pre = itr->second * diftime + m_acce[itr->first] / 2 * diftime * diftime;
      double pre_cos = pre * std::cos (m_radian[itr->first]);
      double pre_sin = pre * std::sin (m_radian[itr->first]);

      m_pre_xpoint[itr->first] = m_xpoint[itr->first] + pre_cos;
      m_pre_ypoint[itr->first] = m_ypoint[itr->first] + pre_sin;
    }
}

//ノード間の関係性を更新するメソッド
// void
// RoutingProtocol::SaveRelation (int32_t map_id, int32_t map_xpoint, int32_t map_ypoint)
// {
//   Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
//   Vector mypos = mobility->GetPosition ();
//   int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
//   int myRoadId = distinctionRoad (mypos.x, mypos.y); //自分の道路ID
//   int NeighborRoadId = distinctionRoad (map_xpoint, map_ypoint); // 近隣ノードの道路ID
//   int currentRelation = 0; //現在ノードとの関係性
//   if (myRoadId == 0 || NeighborRoadId == 0) // どちらかが交差点道路なら
//     {
//       currentRelation = 1; //同一道路なら1
//     }

//   if (myRoadId == NeighborRoadId)
//     {
//       currentRelation = 1; //同一道路なら1
//     }
//   else
//     {
//       currentRelation = 2; //異なる道路なら2
//     }

//   if (m_relation[map_id] != 0) //以前にリンクを持っていたら
//     {
//       if (currentRelation != m_relation[map_id]) //以前と関係性が異なるなら
//         {
//           if (NeighborRoadId == 0 || myRoadId == 0) // どちらかが交差点ノードの場合
//             {
//               currentRelation = m_relation[map_id]; //前の関係性を維持する
//             }
//           else
//             {
//               if (id == 0)
//                 {
//                   std::cout << "以前と関係性が違います　破棄する前の取得数 " << m_recvtime.size ()
//                             << "\n";
//                   std::cout << "関係性が変わった IDは" << id << "pare id" << map_id << "\n";
//                   //m_recvtime.erase (map_id); // helloパケット取得履歴を破棄
//                   std::cout << "破棄後の取得数 " << m_recvtime.size () << "\n";
//                 }
//             }
//         }
//     }
//   m_relation[map_id] = currentRelation; // 現在の関係をマップに保存
// }

void
RoutingProtocol::SaveRecvTime (int32_t map_id, int32_t map_recvtime)
{
  //int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  m_recvtime.insert (std::make_pair (map_id, map_recvtime));
  m_last_recv_time[map_id] = map_recvtime;
}

void
RoutingProtocol::SendXBroadcast (void)
{
}

double
RoutingProtocol::getDistance (double x, double y, double x2, double y2)
{
  double distance = std::sqrt ((x2 - x) * (x2 - x) + (y2 - y) * (y2 - y));

  return distance;
}

double
RoutingProtocol::getAngle (double a_x, double a_y, double b_x, double b_y, double c_x, double c_y)
{
  double BA_x = a_x - b_x; //ベクトルAのｘ座標
  double BA_y = a_y - b_y; //ベクトルAのy座標
  double BC_x = c_x - b_x; //ベクトルCのｘ座標
  double BC_y = c_y - b_y; //ベクトルCのy座標

  double BABC = BA_x * BC_x + BA_y * BC_y;
  double BA_2 = (BA_x * BA_x) + (BA_y * BA_y);
  double BC_2 = (BC_x * BC_x) + (BC_y * BC_y);

  double radian = acos (BABC / (std::sqrt (BA_2 * BC_2)));
  double angle = radian * 180 / 3.14159265; //ラジアンから角度に変換
  return angle;
}

void
RoutingProtocol::SetMyPos (void)
{
  int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
  Vector mypos = mobility->GetPosition ();
  m_my_p_posx[id] = m_my_posx[id]; //過去の座標を登録
  m_my_p_posy[id] = m_my_posy[id];

  m_my_posx[id] = mypos.x; //現在の座標を更新
  m_my_posy[id] = mypos.y;
  // std::cout<<"id"<<id<<"x:"<<m_my_posx[id] << "y:"<<m_my_posy[id] << "\n";
}

void
RoutingProtocol::SetMySpeed (void)
{
  int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
  Vector mypos = mobility->GetPosition ();

  m_my_p_speed[id] = m_my_speed[id]; //過去の秒速度を保存

  double distance = getDistance (mypos.x, mypos.y, m_my_p_posx[id], m_my_p_posy[id]);
  double speed = distance; //秒速(m/s)
  m_my_speed[id] = speed;
}


int
RoutingProtocol::judgeIntersection (int x_point, int y_point)
{
  int interRange = 20; //交差点の半径
  for (auto itr = m_junction_x.begin (); itr != m_junction_x.end (); itr++)
    {
      double distance = getDistance(x_point, y_point, itr->second, m_junction_y[itr->first]);
      if (distance <= interRange) //交差点の内部の座標だったら
      {
        return 0; // on intersection
      }
    }
    return 1; // no intersection node
}


std::string
RoutingProtocol::distinctionRoad (int x_point, int y_point)
{
  int interRange = 20; //交差点の半径

  for (auto itr = m_junction_x.begin (); itr != m_junction_x.end (); itr++)
    {
      double distance = getDistance(x_point, y_point, itr->second, m_junction_y[itr->first]);
      if (distance <= interRange) //交差点の内部の座標だったら
      {
        return itr->first; // junction(intersection) id
      }
    }
    
    std::string separator = "_"; //区切り文字指定
    std::string from_to;
    double min_distance = 1000.0; //数値は仮おき　最小距離の道路にノードは存在する
    std::string road_id;
    for (auto itr = m_road_from_to.begin (); itr != m_road_from_to.end (); itr++)
    {
      from_to = itr->second;
      replace(from_to.begin(), from_to.end(), '_', ' ');
      std::istringstream iss(from_to);

      std::string from, to;
      iss >> from >> to ;  //road = junction from  〜 junction to
      double distance_from = getDistance(m_junction_x[from], m_junction_y[from],x_point, y_point);
      double distance_to = getDistance (m_junction_x[to], m_junction_y[to],x_point, y_point);
      double distance = distance_from + distance_to; //junction fromとtoからの距離が最小になる = その道路に存在する
      
      if(min_distance > distance)
      {
        min_distance = distance;
        road_id = itr->first;
      }
    }

  return road_id; //roadのIDを返す
}

double
RoutingProtocol::lineDistance(double line_x1, double line_y1, double line_x2, double line_y2, 
  double dot_x, double dot_y)
{
  double a,b,c; // ax + by + c = 0
  double root;
  double distance; //求める距離

  a = line_y1 - line_y2;
  b = line_x2 - line_x1;
  c = (-b * line_y1) + (-a * line_x1);
  root = sqrt(a*a + b*b);

  if (root == 0.0) {
    std::cout << " root が求められません" << std::endl;
  }

  distance = ((a * dot_x) + (b * dot_y) + c) / root;

  if (distance < 0.0)
  {
    distance  = -distance;
  }

  return distance;
}



void
RoutingProtocol::SendJbrUnicast (int32_t one_before_x, int32_t one_before_y, int32_t local_source_x, 
  int32_t local_source_y, int32_t previous_x, int32_t previous_y, 
  int32_t des_id, int32_t des_x, int32_t des_y, int32_t hop)
{
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin ();
       j != m_socketAddresses.end (); ++j)
    {
      int32_t id = m_ipv4->GetObject<Node> ()->GetId ();

      Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
      Vector mypos = mobility->GetPosition ();
      
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      Ptr<Packet> packet = Create<Packet> ();

      hop++;
      int32_t next_id = DecisionNextId (one_before_x, one_before_y, local_source_x, local_source_y, 
      previous_x, previous_y,des_x, des_y);


      JbrHeader JbrHeader (id, mypos.x, mypos.y, next_id, local_source_x, local_source_y,
      previous_x, previous_y, des_id, des_x, des_y, hop);
      packet->AddHeader (JbrHeader);

      TypeHeader tHeader (SIGOTYPE_JBR_RECOVER);
      packet->AddHeader (tHeader);

      s_source_id.push_back (id);
      s_source_x.push_back (mypos.x);
      s_source_y.push_back (mypos.y);
      s_time.push_back (Simulator::Now ().GetMicroSeconds ());
      s_hop.push_back (hop);
      s_pri_1_id.push_back (next_id);
      s_pri_2_id.push_back (10000);
      s_pri_3_id.push_back (10000);
      s_pri_4_id.push_back (10000);
      s_pri_5_id.push_back (10000);
      s_pri_1_r.push_back (1); //とりあえず１
      s_pri_2_r.push_back (1);
      s_pri_3_r.push_back (1);
      s_pri_4_r.push_back (1);
      s_pri_5_r.push_back (1);
      s_des_id.push_back (des_id);
      s_send_log.push_back (0); //一旦0にする send関数で本当にsendしたら1 に変える
      m_send_check[des_id] = sendpacketCount;
      s_inter_1_id.push_back (0);
      s_inter_2_id.push_back (0);
      s_inter_3_id.push_back (0);
      s_inter_4_id.push_back (0);
      s_inter_5_id.push_back (0);

      sendpacketCount++;

      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else  //絶対こっちに入る
        {
          destination = iface.GetBroadcast ();
        }
      if (next_id != 10000)
      {
        std::cout << "\n\n *********** id" << id << "recovery"
                << "x=" << mypos.x << "y=" << mypos.y << "recovery unicast  time" << Simulator::Now ().GetSeconds ()
                << "\n";
        std::cout << "next id " << next_id << "\n \n\n\n\n";
        socket->SendTo (packet, 0, InetSocketAddress (destination, SIGO_PORT));
      }else{
        std::cout << "\nrecovery strategy no next hop node | current id" << id <<std::endl;
      }
      
    }
}



int 
RoutingProtocol::DecisionNextId (int32_t one_before_x, int32_t one_before_y, int32_t local_source_x, 
  int32_t local_source_y, int32_t previous_x, int32_t previous_y, int32_t des_x, int32_t des_y)
{
  int existence_intersection = 1; //0 = intersection nodeあり 1 = なし　
  std::cout << "**********id "<<m_ipv4->GetObject<Node> ()->GetId () <<"の近隣テーブル**********\n";
  
  Ptr<MobilityModel> mobility = m_ipv4->GetObject<Node> ()->GetObject<MobilityModel> ();
  Vector current_pos = mobility->GetPosition ();
  std::cout << "このノードのポジションは " << current_pos << std::endl;
  int closest_inter_id = 10000; //junctino node の中で最も宛先に近いノード
  int farthest_simple_id = 10000;  // simple nodeの中で最もcurrent nodeから離れたノード
  int minangle_id = 10000;
  double closest_inter_to_des = 10000; // 最小のintersection nodeとdestinatino nodeの距離を格納
  double farthest_current_des = 0; // current node から最も離れているsimple nodeの距離を格納
  double minimum_angle = 360; //minimum angle method 最小の角度を格納
  std::string current_road_id = distinctionRoad (current_pos.x, current_pos.y);

  for (auto itr = m_xpoint.begin (); itr != m_xpoint.end (); itr++) 
  {
    if (judgeIntersection(itr->second, m_ypoint[itr->first]) == 0) //近隣ノードがintersection node
    {
      int dif_last_recv = Simulator::Now ().GetMicroSeconds () - m_last_recv_time[itr->first];
      if (dif_last_recv < 2200000) //直近２秒でhello packetを受信していたら
      {
        std::cout << "junction neighbor id " << itr->first << "posx " <<
        m_xpoint[itr->first] << "posy " <<  m_ypoint[itr->first]<<  "\n";
        //jbr 条件 1
        double mndis = getDistance (current_pos.x, current_pos.y, 
        m_xpoint[itr->first], m_ypoint[itr->first]); //current to potential 
        double cldis = getDistance (one_before_x, one_before_y, 
        current_pos.x, current_pos.y); // current to one_before
        double nldis = getDistance (m_xpoint[itr->first], m_ypoint[itr->first], 
        one_before_x, one_before_y); // onebefore to potential
        std::cout << "\n nldis " << nldis << "cldis" << cldis << "mndis" << mndis << "\n";
        if(nldis > cldis && nldis > mndis) //jbr  potential nodeの条件
        {
          if(judgeIntersection(current_pos.x, current_pos.y) == 0) //current nodeがcoordinator
          {
            if(distinctionRoad(current_pos.x, current_pos.y) != 
            distinctionRoad(m_xpoint[itr->first], m_ypoint[itr->first])) //同じintersection　じゃなかったら
            {
              if (getDistance (m_xpoint[itr->first], m_ypoint[itr->first], des_x, des_y) < closest_inter_to_des)
              {
                //intersection の中で宛先に近いものを更新していく
                closest_inter_to_des = getDistance (m_xpoint[itr->first], m_ypoint[itr->first], des_x, des_y);
                closest_inter_id = itr->first;
              }
              existence_intersection = 0;
            }else{
              std::cout << "neighbor id" << itr->first << "は 同じ intersection にいる\n"; 
              std::cout <<  "posx " << m_xpoint[itr->first] << "posy " <<  m_ypoint[itr->first]<<  "\n";
            }
          }else{ //current node no coordinator
            std::cout << " current node is no coordinator \n";
            if (getDistance (m_xpoint[itr->first], m_ypoint[itr->first], des_x, des_y) < closest_inter_to_des)
            {
              //intersection の中で宛先に近いものを更新していく
              closest_inter_to_des = getDistance (m_xpoint[itr->first], m_ypoint[itr->first], des_x, des_y);
              closest_inter_id = itr->first;
              std::cout << "今の所 id " << itr->first << "が一番近い\n";
            }
            existence_intersection = 0;
          }
        }
      }
    }else{ //近隣ノードがsimple nodeのみ
      std::cout << "simple neighbor id " << itr->first <<  "\n";
      std::cout <<  "posx " << m_xpoint[itr->first] << "posy " <<  m_ypoint[itr->first]<<  "\n";
      if(judgeIntersection(current_pos.x, current_pos.y) == 0) //current nodeがcoordinator
      {
        //minimum angle method
        double sdangle = getAngle (des_x, des_y, local_source_x, local_source_y,
        previous_x, previous_y);
        double snangle = getAngle (m_xpoint[itr->first], m_ypoint[itr->first], local_source_x, 
        local_source_y, previous_x, previous_y);
        int sdangle_direction = RotationDirection (des_x, des_y, local_source_x, 
        local_source_y, previous_x, previous_y);
        int snangle_direction = RotationDirection (m_xpoint[itr->first], m_ypoint[itr->first], 
        local_source_x, local_source_y, previous_x, previous_y);

        std::cout << "snangle direction" << snangle_direction << "sdangle direction " << sdangle_direction << "\n";

        //符号判定 同じ符号でなければ　角度の回転方向が違えば
        if (signbit(sdangle_direction) != signbit(snangle_direction))
        {
          std::cout << "\n\n id" << itr->first << "角度修正 snagle before" << snangle;
          snangle = 360 - snangle;
          std::cout << "after" << snangle << std::endl;
        }

        double minangle = sdangle - snangle;

        //minangle は絶対値の差
        if (minangle < 0)
        {
          minangle = - minangle;
        }

        std::cout << "neighbor id " << itr->first << "のminangle" << minangle << "\n";
        std::cout << "snangle" << snangle << "sdangle" << sdangle << "\n";
        int dif_last_recv = Simulator::Now ().GetMicroSeconds () - m_last_recv_time[itr->first];
        if (dif_last_recv < 2200000) //直近２秒でhello packetを受信していたら
        {
          if(minangle < minimum_angle)
          {
            minimum_angle = minangle;
            minangle_id = itr->first;
          }
        }
      }else{
        //current nodeから最も離れたノード
        std::string neighbor_road_id = distinctionRoad (m_xpoint[itr->first], m_ypoint[itr->first]);
        int link_judge = LinkRoad (current_road_id ,neighbor_road_id); //linkもってたら1
        int dif_last_recv = Simulator::Now ().GetMicroSeconds () - m_last_recv_time[itr->first];
        if (link_judge == 1) // neighbor が linkを持つことのができるroadだったら
        {
          //jbr 条件 1
          double mndis = getDistance (current_pos.x, current_pos.y, 
          m_xpoint[itr->first], m_ypoint[itr->first]); //current to potential 
          double cldis = getDistance (one_before_x, one_before_y, 
          current_pos.x, current_pos.y); // current to one_before
          double nldis = getDistance (m_xpoint[itr->first], m_ypoint[itr->first], 
          one_before_x, one_before_y); // onebefore to potential
          if(nldis > cldis && nldis > mndis) //jbr  potential nodeの条件
          {
            if (dif_last_recv < 2200000) //直近２秒でhello packetを受信していたら
            {
              if(farthest_current_des < mndis)
              {
                farthest_current_des = mndis;
                farthest_simple_id = itr->first;
              }
            }
            
          }
        }
      }
    }
  }
  if(existence_intersection == 0)
  {
    std::cout << "交差点ノードが存在\n";
    std::cout << "closest intersection node id is " << closest_inter_id << "\n";
    std::cout << "hello packet を取得したのは" << m_last_recv_time[closest_inter_id] << std::endl;
    return closest_inter_id;
  }else {
    std::cout << "交差点ノードが存在しない\n";
    if(judgeIntersection(current_pos.x, current_pos.y) == 0) //current node = coordinator
    {
      std::cout << "minimum angle  node id is " << minangle_id << "\n";
      std::cout << "hello packet を取得したのは" << m_last_recv_time[minangle_id] << std::endl;
      return minangle_id;
    }else{
      std::cout << "farthest simple node id is " << farthest_simple_id << "\n";
      std::cout << "hello packet を取得したのは" << m_last_recv_time[farthest_simple_id] << std::endl;
      return farthest_simple_id;
    }
  }
  return 0;
}



//sumoからnet fileを読み込む
int
RoutingProtocol::ReadSumoFile (void)
{
  //std::ifstream ifs("../../../sumo/tools/no_signal/200/original_net.xml");
  std::ifstream ifs("sumo/tools/no_signal/no_signal_netfile");
  std::string str;

  if (ifs.fail()) {
      std::cerr << "Failed to open file." << std::endl;
      return -1;
  }
  while (getline(ifs, str)) { //1行ずつstrに格納
      std::cout<<"---------------------input road segment -----------------------------\n";
      std::cout << "#" << str << std::endl;
      std::istringstream iss(str);
      std::string split;

      std::vector<std::string> v_road;
      while (iss >> split) {
          v_road.push_back(split);
      }
      if(v_road[0] == "junction") //junction
      {
        std::cout<<"junction id" << v_road[1] <<"\n";
        std::cout<<"junction x" << v_road[2] <<"\n";
        std::cout<<"junction y" << v_road[3] <<"\n";
        m_junction_x[v_road[1]] = stod(v_road[2]);
        m_junction_y[v_road[1]] = stod(v_road[3]);
        std::cout<<"junction x test " << m_junction_x[v_road[1]] <<"\n";
      }
      else{ //road segment
        std::cout<<"road id" << v_road[1] <<"\n";
        std::cout<<"road segment from to" << v_road[2] <<"\n";
        m_road_from_to[v_road[1]] = v_road[2];
        std::cout << " road from to test " <<  m_road_from_to[v_road[1]] << std::endl;
      }

  }
  return 0;
}

int
RoutingProtocol::LinkRoad (std::string current_road_id, std::string neighbor_road_id)
{
  //current road agnle
  std::string current_from_to = m_road_from_to[current_road_id];
  replace(current_from_to.begin(), current_from_to.end(), '_', ' ');
  std::istringstream iss(current_from_to);
  std::string current_from, current_to;
  iss >> current_from >> current_to ;  //road = junction from  〜 junction to
  double current_angle = getTwoPointAngle(m_junction_x[current_from], m_junction_y[current_from],
  m_junction_x[current_to], m_junction_y[current_to]);

  //neighbor road angle
  std::string neighbor_from_to = m_road_from_to[neighbor_road_id];
  replace(neighbor_from_to.begin(), neighbor_from_to.end(), '_', ' ');
  std::istringstream iss2(neighbor_from_to);
  std::string neighbor_from, neighbor_to;
  iss2 >> neighbor_from >> neighbor_to ;  //road = junction from  〜 junction to
  double neighbor_angle = getTwoPointAngle(m_junction_x[neighbor_from], m_junction_y[neighbor_from],
  m_junction_x[neighbor_to], m_junction_y[neighbor_to]);

  double dif_angle = current_angle - neighbor_angle;
  if (dif_angle < 0)
  {
    dif_angle = -dif_angle;
  }

  if (dif_angle < 10) //road同士のangle の差がほぼなければリンクを持つことができる
  {
    return 1;
  }else{
    return 0;
  }
}

int
RoutingProtocol::RotationDirection (double a_x, double a_y, double b_x, double b_y, double c_x,
                   double c_y)
{
  // ※ A = potential node or destiantino node   B = local source node C= previous node
  double BA_x = a_x - b_x; //ベクトルAのｘ座標
  double BA_y = a_y - b_y; //ベクトルAのy座標
  double BC_x = c_x - b_x; //ベクトルCのｘ座標
  double BC_y = c_y - b_y; //ベクトルCのy座標

  int direction = BC_x * BA_y - BA_x * BC_y; 
  // std::cout << "rotation direction check direction = "  << direction <<std::endl;
  return direction;
}

double 
RoutingProtocol::getTwoPointAngle (double x, double y, double x2, double y2)
{
  double radian = atan2(y2 - y,x2 - x);
  double angle = radian * 180 / 3.14159265; //ラジアンから角度に変換
  return angle;
}


//road の中心座標をmapにセットする関数
void
RoutingProtocol::RoadCenterPoint (void)
{
  std::string from_to;
  for (auto itr = m_road_from_to.begin (); itr != m_road_from_to.end (); itr++)
    {
      from_to = itr->second;
      replace(from_to.begin(), from_to.end(), '_', ' ');
      std::istringstream iss(from_to);

      std::string from, to;
      iss >> from >> to ;  //road = junction from  〜 junction to

      m_road_center_x[itr->first] = (m_junction_x[from] + m_junction_x[to]) / 2;
      m_road_center_y[itr->first] = (m_junction_y[from] + m_junction_y[to]) / 2;

    }
}

// シミュレーション結果の出力関数
void
RoutingProtocol::SimulationResult (void) //
{
  std::cout << "time" << Simulator::Now ().GetSeconds () << "\n";
  // int32_t id = m_ipv4->GetObject<Node> ()->GetId ();
  if (Simulator::Now ().GetSeconds () == Grobal_StartTime + Grobal_SourceNodeNum + 1)
    {
      // //*******************************ノードが持つ座標の確認ログ***************************//
      //std::cout << "id=" << id << "の\n";
      // for (auto itr = m_xpoint.begin (); itr != m_xpoint.end (); itr++)
      //   {
      //     std::cout << "recv hello packet id = " << itr->first // キーを表示
      //               << ", x座標 = " << itr->second << "\n"; // 値を表示
      //   }
      // for (auto itr = m_ypoint.begin (); itr != m_ypoint.end (); itr++)
      //   {
      //     std::cout << "recv hello packet id = " << itr->first // キーを表示
      //               << ", y座標 = " << itr->second << "\n"; // 値を表示
      //   }
      //**************************************************************************************//

      //*******************************ノードが持つ受信時刻ログ***************************//
      // if (id == 14)
      //   std::cout << "id=" << id << "recv数" << m_recvtime.size () << "\n";

      // auto itr = m_recvtime.find (1);
      // if (itr != m_recvtime.end ())
      //   { // 見つかった場合
      //     for (auto itr = m_recvtime.begin (); itr != m_recvtime.end (); itr++)
      //       {
      //         std::cout << itr->first << " " << itr->second << "\n"; //  キー、値を表示
      //       }
      //   }
      // itr = m_recvtime.find (1);
      // if (itr == m_recvtime.end ())
      //   { // 見つからなかった場合
      //     std::cout << "not found.\n";
      //   }
      //**************************************************************************************//
      int sum_end_time = 0;
      int sum_br = 0; //ブロードキャスト数の平均
      double average_end_time = 0;
      int recvCount = 0;
      std::cout << "\n\n\n結果出力----------------------------------\n\n";
      for (auto itr = broadcount.begin (); itr != broadcount.end (); itr++)
        {
          std::cout << "des id " << itr->first << "sigo broadcast数" << broadcount[itr->first]
                    << "\n";
          sum_br += broadcount[itr->first];
        }
      for (auto itr = m_start_time.begin (); itr != m_start_time.end (); itr++)
        {
          std::cout << "des id " << itr->first << "送信開始時刻" << m_start_time[itr->first]
                    << "\n";
        }
      for (auto itr = m_finish_time.begin (); itr != m_finish_time.end (); itr++)
        {
          if (m_finish_time[itr->first] != 0) // 受信回数分回る
            {
              std::cout << "des id " << itr->first << "受信時刻" << m_finish_time[itr->first]
                        << "\n";
              int end_to_end_time = m_finish_time[itr->first] - m_start_time[itr->first];
              sum_end_time += end_to_end_time;
              std::cout << "destination id = " << itr->first
                        << "end to end deley time = " << end_to_end_time << "\n";
              recvCount++;
            }
        }

      std::cout << "sum_br" << sum_br << "\n";
      std::cout << "recvCount" << recvCount << "\n";
      std::cout << "sum_end_time" << sum_end_time << "\n";
      std::cout << "max Lenge" << maxLenge << "\n";
      double average_overhead = (double) sum_br / (double) recvCount;
      double packet_recv_rate = (double) recvCount / (double) m_start_time.size ();
      average_end_time = (double) sum_end_time / (double) recvCount;
      std::cout << "本シミュレーションのパケット到達率は" << packet_recv_rate << "\n";
      std::cout << "本シミュレーションのパケットEnd to End遅延時間は" << average_end_time << "\n";
      std::cout << "本シミュレーションのパケット平均オーバーヘッドは" << average_overhead << "\n";
      std::cout << "交差点ノードにおける重み付けは" << Grobal_InterPoint << "\n";
      std::cout << "本シミュレーションのシミュレーション開始時刻は" << Grobal_StartTime << "\n";
      std::cout << "送信数は" << m_start_time.size () << "\n";
      std::cout << "受信数は" << recvCount << "\n";
      std::cout << "PDRテスト" << m_finish_time.size () / m_start_time.size () << "\n";
      std::cout << "Seed値は" << Grobal_Seed << "\n";
      std::cout << "車両数は" << numVehicle << "\n";
      std::cout << "trans probability" << TransProbability << "\n";

      std::string filename;
      std::string send_filename;

      if(Buildings == 1)
      {
        // std::string shadow_dir = "data/get_data/" + std::to_string(Grobal_m_beta) + "_" + std::to_string (Grobal_m_gamma) 
        // + "/" + std::to_string (Grobal_InterPoint);
        //　書き出し pass
        std::string shadow_dir = "data/get_data/recover/shadow" + std::to_string(Grobal_m_beta) + "_" + std::to_string (Grobal_m_gamma);
        std::cout<<"shadowing packet csv \n";

        if(Grobal_recovery_protocol == 0)
        {
          //ファイル名そのまま
          std::cout << "\n\n\n  sigo no recovery output\n";
          filename = shadow_dir + "/sigo/sigo-seed_" + std::to_string (Grobal_Seed) + "nodenum_" +
                              std::to_string (numVehicle) + ".csv";
          send_filename = shadow_dir + "/send_sigo/sigo-seed_" + std::to_string (Grobal_Seed) + "nodenum_" +
                                    std::to_string (numVehicle) + ".csv";          
        }else if(Grobal_recovery_protocol == 1)
        {
          std::cout << "\n\n\n  sigo sigo recovery output\n";
          filename = shadow_dir + "/sigo_recover/sigo-seed_" + std::to_string (Grobal_Seed) + "nodenum_" +
                              std::to_string (numVehicle) + ".csv";
          send_filename = shadow_dir + "/send_sigo_recover/sigo-seed_" + std::to_string (Grobal_Seed) + "nodenum_" +
                                    std::to_string (numVehicle) + ".csv";
        }else if(Grobal_recovery_protocol == 2)
        {
          std::cout << "\n\n\n  sigo jbr recovery output\n";
          filename = shadow_dir + "/jbr/sigo-seed_" + std::to_string (Grobal_Seed) + "nodenum_" +
                              std::to_string (numVehicle) + ".csv";
          send_filename = shadow_dir + "/send_jbr/sigo-seed_" + std::to_string (Grobal_Seed) + "nodenum_" +
                                    std::to_string (numVehicle) + ".csv";
        }else {
          //gpcr
        }
        
        const char *dir = shadow_dir.c_str();
        struct stat statBuf;

        if (stat(dir, &statBuf) != 0) //directoryがなかったら
        {
          std::cout<<"ディレクトリが存在しないので作成します\n";
          mkdir(dir, S_IRWXU);
        }

        std::string s_sigo_dir;
        std::string  s_send_sigo_dir;
        

        if(Grobal_recovery_protocol == 0)
        {
          //ファイル名そのまま
          s_sigo_dir = shadow_dir + "/sigo";
          s_send_sigo_dir = shadow_dir + "/send_sigo";

        }else if(Grobal_recovery_protocol == 1)
        {
          s_sigo_dir = shadow_dir + "/sigo_recover";
          s_send_sigo_dir = shadow_dir + "/send_sigo_recover";

        }else if(Grobal_recovery_protocol == 2)
        {
          s_sigo_dir = shadow_dir + "/jbr";
          s_send_sigo_dir = shadow_dir + "/send_jbr";
        }else {
          //gpcr
        }

        const char * c_sigo_dir = s_sigo_dir.c_str();
        const char * c_send_sigo_dir = s_send_sigo_dir.c_str();
        if(stat(c_sigo_dir, &statBuf) != 0)
        {
          mkdir(c_sigo_dir, S_IRWXU);
          mkdir(c_send_sigo_dir, S_IRWXU);
        }
      }
      else{
        std::cout<<"no_shadowing packet csv \n";
        filename = "data/no_buildings/sigo/sigo-seed_" + std::to_string (Grobal_Seed) + "nodenum_" +
                             std::to_string (numVehicle) + ".csv";
        send_filename = "data/no_buildings/send_sigo/sigo-seed_" + std::to_string (Grobal_Seed) + "nodenum_" +
                                  std::to_string (numVehicle) + ".csv";
      }

      std::ofstream packetTrajectory (filename);
      packetTrajectory << "source_x"
                       << ","
                       << "source_y"
                       << ","
                       << "recv_x"
                       << ","
                       << "recv_y"
                       << ","
                       << "time"
                       << ","
                       << "recv_priority"
                       << ","
                       << "hopcount"
                       << ","
                       << "recv_id"
                       << ","
                       << "source_id"
                       << ","
                       << "destination_id"
                       << ","
                       << "destination_x"
                       << ","
                       << "destination_y"
                       << ","
                       << "pri_1"
                       << ","
                       << "pri_2"
                       << ","
                       << "pri_3"
                       << ","
                       << "pri_4"
                       << ","
                       << "pri_5"
                       << ","
                       << "pri_recover" << std::endl;

      std::ofstream send_packetTrajectory (send_filename);
      send_packetTrajectory << "source_id"
                            << ","
                            << "source_x"
                            << ","
                            << "source_y"
                            << ","
                            << "time"
                            << ","
                            << "hop"
                            << ","
                            << "pri_1_id"
                            << ","
                            << "pri_2_id"
                            << ","
                            << "pri_3_id"
                            << ","
                            << "pri_4_id"
                            << ","
                            << "pri_5_id"
                            << ","
                            << "pri_1_r"
                            << ","
                            << "pri_2_r"
                            << ","
                            << "pri_3_r"
                            << ","
                            << "pri_4_r"
                            << ","
                            << "pri_5_r"
                            << ","
                            << "des_id"
                            << ","
                            << "inter_1id "
                            << ","
                            << "inter_2id "
                            << ","
                            << "inter_3id "
                            << ","
                            << "inter_4id "
                            << ","
                            << "inter_5id " 
                            << ","
                            << "send_log"<< std::endl;

      for (int i = 0; i < packetCount; i++)
        {

          packetTrajectory << p_source_x[i] << ", " << p_source_y[i] << ", " << p_recv_x[i] << ", "
                           << p_recv_y[i] << ", " << p_recv_time[i] << ", " << p_recv_priority[i]
                           << ", " << p_hopcount[i] << ", " << p_recv_id[i] << ", "
                           << p_source_id[i] << ", " << p_destination_id[i] << ", "
                           << p_destination_x[i] << ", " << p_destination_y[i] << ", " << p_pri_1[i]
                           << ", " << p_pri_2[i] << ", " << p_pri_3[i] << ", " << p_pri_4[i] << ", "
                           << p_pri_5[i] << ", " << p_recovery[i] << std::endl;
        }
      for (int i = 0; i < sendpacketCount; i++)
        {
          send_packetTrajectory << s_source_id[i] << ", " << s_source_x[i] << ", " << s_source_y[i]
                                << ", " << s_time[i] << ", " << s_hop[i] << ", " << s_pri_1_id[i]
                                << ", " << s_pri_2_id[i] << ", " << s_pri_3_id[i] << ", "
                                << s_pri_4_id[i] << ", " << s_pri_5_id[i] << ", " << s_pri_1_r[i]
                                << ", " << s_pri_2_r[i] << ", " << s_pri_3_r[i] << ", "
                                << s_pri_4_r[i] << ", " << s_pri_5_r[i] << ", " << s_des_id[i]
                                << ", " << s_inter_1_id[i] << ", " << s_inter_2_id[i] << ", "
                                << s_inter_3_id[i] << ", " << s_inter_4_id[i] << ", "
                                << s_inter_5_id[i] << ", " << s_send_log[i] << std::endl;
        }
    }
}

std::map<int, int> RoutingProtocol::broadcount; //key 0 value broudcast数
std::map<int, int> RoutingProtocol::m_start_time; //key destination_id value　送信時間
std::map<int, int> RoutingProtocol::m_finish_time; //key destination_id value 受信時間
std::map<int, double> RoutingProtocol::m_my_posx; // key node id value position x
std::map<int, double> RoutingProtocol::m_my_posy; // key node id value position y
std::map<int, double> RoutingProtocol::m_my_p_posx; // key node id value past position x
std::map<int, double> RoutingProtocol::m_my_p_posy; // key node id value past position y
std::map<int, double> RoutingProtocol::m_my_speed; // key node id value current speed
std::map<int, double> RoutingProtocol::m_my_p_speed; // key node id value past speed
std::map<int, double> RoutingProtocol::m_my_acce; //key node id value acceleration(加速度)
std::map<std::string, double> RoutingProtocol::m_junction_x; // key junction id value xposition
std::map<std::string, double> RoutingProtocol::m_junction_y; // key junction id value yposition
std::map<std::string, double> RoutingProtocol:: m_road_center_x;  // key road id value road center position x
std::map<std::string, double> RoutingProtocol:: m_road_center_y;  // key road id value road center position y
std::map<std::string, std::string> RoutingProtocol::m_road_from_to; // key road id value junction from to
std::vector<int> RoutingProtocol::source_list;
std::vector<int> RoutingProtocol::des_list;

//パケット軌跡出力用の変数
std::vector<int> RoutingProtocol::p_source_x;
std::vector<int> RoutingProtocol::p_source_y;
std::vector<int> RoutingProtocol::p_recv_x;
std::vector<int> RoutingProtocol::p_recv_y;
std::vector<int> RoutingProtocol::p_recv_time;
std::vector<int> RoutingProtocol::p_recv_priority;
std::vector<int> RoutingProtocol::p_hopcount;
std::vector<int> RoutingProtocol::p_recv_id;
std::vector<int> RoutingProtocol::p_source_id;
std::vector<int> RoutingProtocol::p_destination_id;
std::vector<int> RoutingProtocol::p_destination_x;
std::vector<int> RoutingProtocol::p_destination_y;
std::vector<int> RoutingProtocol::p_pri_1;
std::vector<int> RoutingProtocol::p_pri_2;
std::vector<int> RoutingProtocol::p_pri_3;
std::vector<int> RoutingProtocol::p_pri_4;
std::vector<int> RoutingProtocol::p_pri_5;
std::vector<int> RoutingProtocol::p_recovery;

//送信側ログ用変数
std::vector<int> RoutingProtocol::s_source_id;
std::vector<int> RoutingProtocol::s_source_x;
std::vector<int> RoutingProtocol::s_source_y;
std::vector<int> RoutingProtocol::s_time;
std::vector<int> RoutingProtocol::s_hop;
std::vector<int> RoutingProtocol::s_pri_1_id;
std::vector<int> RoutingProtocol::s_pri_2_id;
std::vector<int> RoutingProtocol::s_pri_3_id;
std::vector<int> RoutingProtocol::s_pri_4_id;
std::vector<int> RoutingProtocol::s_pri_5_id;
std::vector<double> RoutingProtocol::s_pri_1_r;
std::vector<double> RoutingProtocol::s_pri_2_r;
std::vector<double> RoutingProtocol::s_pri_3_r;
std::vector<double> RoutingProtocol::s_pri_4_r;
std::vector<double> RoutingProtocol::s_pri_5_r;
std::vector<int> RoutingProtocol::s_des_id;
std::vector<int> RoutingProtocol::s_inter_1_id; //文字列で交差点にいるIDをぶち込む
std::vector<int> RoutingProtocol::s_inter_2_id;
std::vector<int> RoutingProtocol::s_inter_3_id;
std::vector<int> RoutingProtocol::s_inter_4_id;
std::vector<int> RoutingProtocol::s_inter_5_id;
std::vector<int> RoutingProtocol::s_send_log;

} // namespace sigo
} // namespace ns3
