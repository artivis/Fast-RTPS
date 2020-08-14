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
 * @file SecurityLoggingSubscriber.cpp
 *
 */

#include "SecurityLoggingSubscriber.h"
#include <fastrtps/participant/Participant.h>
#include <fastrtps/attributes/ParticipantAttributes.h>
#include <fastrtps/attributes/SubscriberAttributes.h>
#include <fastrtps/subscriber/Subscriber.h>
#include <fastrtps/Domain.h>

using namespace eprosima::fastrtps;
using namespace eprosima::fastrtps::rtps;

bool SecurityLoggingSubscriber::init()
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
//                    "file:///home/ubuntu/ros2_ws/src/eProsima/Fast-RTPS/examples/C++/SecurityLoggingSubscriberExample/certs/permissions.smime"));
//    participant_property_policy.properties().emplace_back("dds.sec.crypto.plugin",
//                "builtin.AES-GCM-GMAC");

    const std::string keystore = "file:///home/ubuntu/ros2_ws/src/eProsima/Fast-RTPS/examples/C++/SecurityLoggingSubscriberExample"
//                                 "/keystore_noenc/enclaves/talker_listener/security_listener/";
                                 "/keystore/enclaves/talker_listener/security_listener/";

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

    participant_property_policy.properties().emplace_back("dds.sec.crypto.plugin", "builtin.AES-GCM-GMAC");

    PParam.rtps.properties = participant_property_policy;

    mp_participant = Domain::createParticipant(PParam);

    if (mp_participant == nullptr) {
        return false;
    }

    //REGISTER THE TYPE

    Domain::registerType(mp_participant,&m_type);
    //CREATE THE SUBSCRIBER
    SubscriberAttributes Rparam;
    Rparam.topic.topicKind = NO_KEY;
    Rparam.topic.topicDataType = "BuiltinLoggingType";
    Rparam.topic.topicName = "DDS:Security:LogTopic";
    Rparam.topic.historyQos.kind = KEEP_LAST_HISTORY_QOS;
    Rparam.topic.historyQos.depth = 30;
    Rparam.topic.resourceLimitsQos.max_samples = 50;
    Rparam.topic.resourceLimitsQos.allocated_samples = 20;
    Rparam.qos.m_reliability.kind = RELIABLE_RELIABILITY_QOS;
    Rparam.qos.m_durability.kind = VOLATILE_DURABILITY_QOS;

    mp_subscriber = Domain::createSubscriber(mp_participant,Rparam,(SubscriberListener*)&m_listener);

    if (mp_subscriber == nullptr) {
        return false;
    }

    return true;
}

SecurityLoggingSubscriber::~SecurityLoggingSubscriber() {
    // TODO Auto-generated destructor stub
    Domain::removeParticipant(mp_participant);
}

void SecurityLoggingSubscriber::SubListener::onSubscriptionMatched(Subscriber* /*sub*/, MatchingInfo& info)
{
    if (info.status == MATCHED_MATCHING)
    {
        n_matched++;
        logInfo(SECURITY, "\n\n\n!!!!Subscriber matched!!!!\n\n\n");
    }
    else
    {
        n_matched--;
        logInfo(SECURITY, "\n\n\n!!!!Subscriber NOT matched!!!!\n\n\n");
    }
}

void SecurityLoggingSubscriber::SubListener::onNewDataMessage(Subscriber* sub)
{
    if (sub->takeNextData((void*)&m_msg, &m_info))
    {
        if (m_info.sampleKind == ALIVE)
        {
            this->n_samples++;

            // Print your structure data here.
            security::SecurityException e;
            std::string s_severity;
            security::LogLevel_to_string(m_msg.severity, s_severity, e);

            std::stringstream ss;

            ss << "\n\nMessage: \n"
               << m_msg.facility << "\n"
               << s_severity << "\n"
               << "Stamp: " << std::setprecision (std::numeric_limits<double>::digits10 + 1) << m_msg.timestamp << "\n"
               << m_msg.hostname << "\n"
               << m_msg.hostip << "\n"
               << m_msg.appname << "\n"
               << m_msg.procid << "\n"
               << m_msg.msgid << "\n"
               << m_msg.message << "\n";

            for (const auto& sd : m_msg.structured_data)
            {
              ss << sd.first << ":";
              for (const auto& nvp : sd.second)
              {
                ss << "\t" << nvp.name << " : " << nvp.value << "\n";
              }
              ss << "\n";
            }
            ss << std::endl;

            const auto str = ss.str();
//            logError(EXAMPLE, str);
            std::cout << str << std::endl;
        }
    }
}

void SecurityLoggingSubscriber::run()
{
    std::cout << "Subscriber running. Please press enter to stop the Subscriber" << std::endl;
    std::cin.ignore();
}
