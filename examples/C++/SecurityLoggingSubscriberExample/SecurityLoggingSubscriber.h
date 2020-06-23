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
 * @file SecurityLoggingSubscriber.h
 *
 */

#ifndef SecurityLoggingSubscriber_H_
#define SecurityLoggingSubscriber_H_

#include "../SecureHelloWorldExample/HelloWorldPubSubTypes.h"

#include <fastrtps/fastrtps_fwd.h>
#include <fastrtps/attributes/SubscriberAttributes.h>
#include <fastrtps/subscriber/SubscriberListener.h>
#include <fastrtps/subscriber/SampleInfo.h>

#include <fastdds/rtps/security/logging/BuiltinLoggingTypePubSubTypes.h>

class SecurityLoggingSubscriber {
public:

	SecurityLoggingSubscriber() = default;
	virtual ~SecurityLoggingSubscriber();
	//!Initialize the subscriber
	bool init();
	//!RUN the subscriber
  void run();

private:

	eprosima::fastrtps::Participant* mp_participant = nullptr;
	eprosima::fastrtps::Subscriber* mp_subscriber = nullptr;

public:

	class SubListener : public eprosima::fastrtps::SubscriberListener
	{
	public:
		SubListener() = default;
		~SubListener() = default;
		void onSubscriptionMatched(eprosima::fastrtps::Subscriber* sub, eprosima::fastrtps::rtps::MatchingInfo& info);
		void onNewDataMessage(eprosima::fastrtps::Subscriber* sub);
    eprosima::fastrtps::rtps::security::BuiltinLoggingType m_msg;
		eprosima::fastrtps::SampleInfo_t m_info;
		int n_matched = 0;
		uint32_t n_samples = 0;
	} m_listener;
private:
   eprosima::fastrtps::rtps::security::BuiltinLoggingTypePubSubType m_type;
};

#endif /* SecurityLoggingSubscriber_H_ */
