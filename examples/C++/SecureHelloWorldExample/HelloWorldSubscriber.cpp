// Copyright 2016 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @file HelloWorldSubscriber.cpp
 *
 */

#include "HelloWorldSubscriber.h"
#include <fastrtps/participant/Participant.h>
#include <fastrtps/attributes/ParticipantAttributes.h>
#include <fastrtps/attributes/SubscriberAttributes.h>
#include <fastrtps/subscriber/Subscriber.h>
#include <fastrtps/Domain.h>

using namespace eprosima::fastrtps;
using namespace eprosima::fastrtps::rtps;

HelloWorldSubscriber::HelloWorldSubscriber():mp_participant(nullptr),
mp_subscriber(nullptr)
{
}

bool HelloWorldSubscriber::init()
{
    ParticipantAttributes PParam;

    PropertyPolicy participant_property_policy;
//    participant_property_policy.properties().emplace_back("dds.sec.auth.plugin",
//                "builtin.PKI-DH");
//    participant_property_policy.properties().emplace_back("dds.sec.auth.builtin.PKI-DH.identity_ca",
//                    "file:///home/ubuntu/ros2_ws/src/eProsima/Fast-RTPS/examples/C++/SecureHelloWorldExample/certs/maincacert.pem");
//    participant_property_policy.properties().emplace_back("dds.sec.auth.builtin.PKI-DH.identity_certificate",
//                    "file:///home/ubuntu/ros2_ws/src/eProsima/Fast-RTPS/examples/C++/SecureHelloWorldExample/certs/mainsubcert.pem");
//    participant_property_policy.properties().emplace_back("dds.sec.auth.builtin.PKI-DH.private_key",
//                    "file:///home/ubuntu/ros2_ws/src/eProsima/Fast-RTPS/examples/C++/SecureHelloWorldExample/certs/mainsubkey.pem");
//    participant_property_policy.properties().emplace_back(Property("dds.sec.access.plugin",
//                    "builtin.Access-Permissions"));
//    participant_property_policy.properties().emplace_back(Property("dds.sec.access.builtin.Access-Permissions.permissions_ca",
//                    "file:///home/ubuntu/ros2_ws/src/eProsima/Fast-RTPS/examples/C++/SecureHelloWorldExample/certs/maincacert.pem"));
//    participant_property_policy.properties().emplace_back(Property("dds.sec.access.builtin.Access-Permissions.governance",
//                    "file:///home/ubuntu/ros2_ws/src/eProsima/Fast-RTPS/examples/C++/SecureHelloWorldExample/certs/governance.smime"));
//    participant_property_policy.properties().emplace_back(Property("dds.sec.access.builtin.Access-Permissions.permissions",
//                    "file:///home/ubuntu/ros2_ws/src/eProsima/Fast-RTPS/examples/C++/SecureHelloWorldExample/certs/permissions.smime"));
//    participant_property_policy.properties().emplace_back("dds.sec.crypto.plugin",
//                "builtin.AES-GCM-GMAC");

    const std::string keystore = "file:///home/ubuntu/ros2_ws/src/eProsima/Fast-RTPS/examples/C++/SecurityLoggingSubscriberExample/my_keystore/enclaves/talker_listener/listener/";

    participant_property_policy.properties().emplace_back("dds.sec.auth.plugin", "builtin.PKI-DH");

    participant_property_policy.properties().emplace_back("dds.sec.auth.builtin.PKI-DH.identity_ca",
                    keystore + "identity_ca.cert.pem");

    participant_property_policy.properties().emplace_back("dds.sec.auth.builtin.PKI-DH.identity_certificate",
                    keystore + "cert.pem");

    participant_property_policy.properties().emplace_back("dds.sec.auth.builtin.PKI-DH.private_key",
                    keystore + "key.pem");

    participant_property_policy.properties().emplace_back(Property("dds.sec.access.plugin", "builtin.Access-Permissions"));

    participant_property_policy.properties().emplace_back(Property("dds.sec.access.builtin.Access-Permissions.permissions_ca",
                    keystore + "permissions_ca.cert.pem"));

    participant_property_policy.properties().emplace_back(Property("dds.sec.access.builtin.Access-Permissions.governance",
                    keystore + "governance.p7s"));

    participant_property_policy.properties().emplace_back(Property("dds.sec.access.builtin.Access-Permissions.permissions",
                    keystore + "permissions.p7s"));

    participant_property_policy.properties().emplace_back("dds.sec.crypto.plugin",
                    "builtin.AES-GCM-GMAC");

    participant_property_policy.properties().emplace_back("dds.sec.log.plugin",
                "builtin.DDS_LogTopic");
    participant_property_policy.properties().emplace_back("dds.sec.log.builtin.DDS_LogTopic.distribute",
                "true");
    participant_property_policy.properties().emplace_back("dds.sec.log.builtin.DDS_LogTopic.logging_level",
                "DEBUG_LEVEL");
    participant_property_policy.properties().emplace_back("dds.sec.log.builtin.DDS_LogTopic.log_file",
                "/tmp/security.log");

    PParam.rtps.properties = participant_property_policy;

    mp_participant = Domain::createParticipant(PParam);
    if(mp_participant==nullptr)
        return false;

    //REGISTER THE TYPE

    Domain::registerType(mp_participant,&m_type);
    //CREATE THE SUBSCRIBER
    SubscriberAttributes Rparam;
    Rparam.topic.topicKind = NO_KEY;
    Rparam.topic.topicDataType = "HelloWorld";
    Rparam.topic.topicName = "HelloWorldTopic";
    Rparam.topic.historyQos.kind = KEEP_LAST_HISTORY_QOS;
    Rparam.topic.historyQos.depth = 30;
    Rparam.topic.resourceLimitsQos.max_samples = 50;
    Rparam.topic.resourceLimitsQos.allocated_samples = 20;
    Rparam.qos.m_reliability.kind = RELIABLE_RELIABILITY_QOS;

    mp_subscriber = Domain::createSubscriber(mp_participant,Rparam,(SubscriberListener*)&m_listener);

    if(mp_subscriber == nullptr)
        return false;


    return true;
}

HelloWorldSubscriber::~HelloWorldSubscriber() {
    // TODO Auto-generated destructor stub
    Domain::removeParticipant(mp_participant);
}

void HelloWorldSubscriber::SubListener::onSubscriptionMatched(Subscriber* /*sub*/,MatchingInfo& info)
{
    if(info.status == MATCHED_MATCHING)
    {
        n_matched++;
        std::cout << "Subscriber matched"<<std::endl;
    }
    else
    {
        n_matched--;
        std::cout << "Subscriber unmatched"<<std::endl;
    }
}

void HelloWorldSubscriber::SubListener::onNewDataMessage(Subscriber* sub)
{
    if(sub->takeNextData((void*)&m_Hello, &m_info))
    {
        if(m_info.sampleKind == ALIVE)
        {
            this->n_samples++;
            // Print your structure data here.
            std::cout << "Message "<<m_Hello.message()<< " "<< m_Hello.index()<< " RECEIVED"<<std::endl;
        }
    }

}


void HelloWorldSubscriber::run()
{
    std::cout << "Subscriber running. Please press enter to stop the Subscriber" << std::endl;
    std::cin.ignore();
}

void HelloWorldSubscriber::run(uint32_t number)
{
    std::cout << "Subscriber running until "<< number << "samples have been received"<<std::endl;
    while(number < this->m_listener.n_samples)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}
