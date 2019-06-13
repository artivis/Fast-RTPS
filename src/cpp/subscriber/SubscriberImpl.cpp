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
 * @file SubscriberImpl.cpp
 *
 */

#include "SubscriberImpl.h"
#include "../participant/ParticipantImpl.h"
#include <fastrtps/subscriber/Subscriber.h>
#include <fastrtps/topic/TopicDataType.h>
#include <fastrtps/subscriber/SubscriberListener.h>
#include <fastrtps/rtps/reader/RTPSReader.h>
#include <fastrtps/rtps/reader/StatefulReader.h>
#include <fastrtps/rtps/RTPSDomain.h>
#include <fastrtps/rtps/participant/RTPSParticipant.h>
#include <fastrtps/rtps/resources/ResourceEvent.h>

#include <fastrtps/log/Log.h>

using namespace eprosima::fastrtps::rtps;
using namespace std::chrono;

namespace eprosima {
namespace fastrtps {


SubscriberImpl::SubscriberImpl(
        ParticipantImpl* p,
        const SubscriberAttributes& att,
        SubscriberListener* listen)
    : mp_participant(p)
    , m_att(att)
#pragma warning (disable : 4355 )
    , mp_listener(listen)
    , m_readerListener(this)
    , mp_userSubscriber(nullptr)
    , mp_rtpsParticipant(nullptr)
    , deadline_timer_(std::bind(&SubscriberImpl::deadline_missed, this),
                      att.qos.m_deadline.period.to_ns() * 1e-6,
                      mp_participant->get_resource_event().getIOService(),
                      mp_participant->get_resource_event().getThread())
    , deadline_duration_us_(m_att.qos.m_deadline.period.to_ns() * 1e-3)
    , deadline_missed_status_()
    , lifespan_timer_(std::bind(&SubscriberImpl::lifespan_expired, this),
                      m_att.qos.m_lifespan.duration.to_ns() * 1e-6,
                      mp_participant->get_resource_event().getIOService(),
                      mp_participant->get_resource_event().getThread())
    , lifespan_duration_us_(m_att.qos.m_lifespan.duration.to_ns() * 1e-3)
{
}

SubscriberImpl::~SubscriberImpl()
{
    if(mp_reader != nullptr)
    {
        logInfo(SUBSCRIBER,this->getGuid().entityId << " in topic: "<<this->m_att.topic.topicName);
    }

    RTPSDomain::removeRTPSReader(mp_reader);
    delete(this->mp_userSubscriber);
}

RTPSReader* SubscriberImpl::create_reader(
        const TopicAttributes& topic_att)
{
    logInfo(PARTICIPANT, "CREATING READER IN TOPIC: " << topic_att.getTopicName())
    //Look for the correct type registration

    TopicDataType* topic_data_type = mp_participant->get_registered_type(topic_att.topicDataType.c_str());

    if(topic_data_type == nullptr)
    {
        logError(SUBSCRIBER, "Type: "<< topic_att.getTopicDataType() << " Not Registered");
        return nullptr;
    }
    if(topic_att.topicKind == WITH_KEY && !topic_data_type->m_isGetKeyDefined)
    {
        logError(SUBSCRIBER, "Keyed Topic " << topic_att.getTopicName() << " needs getKey function");
        return nullptr;
    }

    if(!topic_att.checkQos())
    {
        return nullptr;
    }

    ReaderAttributes ratt;
    ratt.endpoint.durabilityKind = m_att.qos.m_durability.durabilityKind();
    ratt.endpoint.endpointKind = READER;
    ratt.endpoint.multicastLocatorList = m_att.multicastLocatorList;
    ratt.endpoint.reliabilityKind = m_att.qos.m_reliability.kind == RELIABLE_RELIABILITY_QOS ? RELIABLE : BEST_EFFORT;
    ratt.endpoint.topicKind = topic_att.topicKind;
    ratt.endpoint.unicastLocatorList = m_att.unicastLocatorList;
    ratt.endpoint.remoteLocatorList = m_att.remoteLocatorList;
    ratt.expectsInlineQos = m_att.expectsInlineQos;
    ratt.endpoint.properties = m_att.properties;
    if(m_att.getEntityID()>0)
        ratt.endpoint.setEntityID((uint8_t)m_att.getEntityID());
    if(m_att.getUserDefinedID()>0)
        ratt.endpoint.setUserDefinedID((uint8_t)m_att.getUserDefinedID());
    ratt.times = m_att.times;

    // TODO(Ricardo) Remove in future
    // Insert topic_name and partitions
    Property property;
    property.name("topic_name");
    property.value(topic_att.getTopicName().c_str());
    ratt.endpoint.properties.properties().push_back(std::move(property));
    if(m_att.qos.m_partition.getNames().size() > 0)
    {
        property.name("partitions");
        std::string partitions;
        for(auto partition : m_att.qos.m_partition.getNames())
        {
            partitions += partition + ";";
        }
        property.value(std::move(partitions));
        ratt.endpoint.properties.properties().push_back(std::move(property));
    }
    if (m_att.qos.m_disablePositiveACKs.enabled)
    {
        ratt.disable_positive_acks = true;
    }

    SubscriberHistory history(this,
                              topic_data_type->m_typeSize  + 3/*Possible alignment*/,
                              topic_att.historyQos,
                              topic_att.resourceLimitsQos,
                              m_att.historyMemoryPolicy);

    RTPSReader* reader = RTPSDomain::createRTPSReader(this->mp_rtpsParticipant,
            ratt,
            (ReaderHistory*)&history,
            (ReaderListener*)&m_readerListener);

    if(reader == nullptr)
    {
        logError(PARTICIPANT,"Problem creating associated Reader");
        return nullptr;
    }
    mp_readers[reader->getGuid()] = reader;
    mp_types[reader->getGuid()] = topic_data_type;
    m_histories[reader->getGuid()] = std::move(history);

    //REGISTER THE READER
    mp_rtpsParticipant->registerReader(reader, topic_att, m_att.qos);
}

void SubscriberImpl::waitForUnreadMessage()
{
    if(m_history.getUnreadCount()==0)
    {
        do
        {
            m_history.waitSemaphore();
        }
        while(m_history.getUnreadCount() == 0);
    }
}

bool SubscriberImpl::readNextData(void* data,SampleInfo_t* info)
{
    return this->m_history.readNextData(data,info);
}

bool SubscriberImpl::takeNextData(void* data,SampleInfo_t* info)
{
    return this->m_history.takeNextData(data,info);
}

const GUID_t& SubscriberImpl::getGuid()
{
    return mp_reader->getGuid();
}

bool SubscriberImpl::updateAttributes(const SubscriberAttributes& att)
{
    bool updated = true;
    bool missing = false;
    if(att.unicastLocatorList.size() != this->m_att.unicastLocatorList.size() ||
            att.multicastLocatorList.size() != this->m_att.multicastLocatorList.size())
    {
        logWarning(RTPS_READER,"Locator Lists cannot be changed or updated in this version");
        updated &= false;
    }
    else
    {
        for(LocatorListConstIterator lit1 = this->m_att.unicastLocatorList.begin();
                lit1!=this->m_att.unicastLocatorList.end();++lit1)
        {
            missing = true;
            for(LocatorListConstIterator lit2 = att.unicastLocatorList.begin();
                    lit2!= att.unicastLocatorList.end();++lit2)
            {
                if(*lit1 == *lit2)
                {
                    missing = false;
                    break;
                }
            }
            if(missing)
            {
                logWarning(RTPS_READER,"Locator: "<< *lit1 << " not present in new list");
                logWarning(RTPS_READER,"Locator Lists cannot be changed or updated in this version");
            }
        }
        for(LocatorListConstIterator lit1 = this->m_att.multicastLocatorList.begin();
                lit1!=this->m_att.multicastLocatorList.end();++lit1)
        {
            missing = true;
            for(LocatorListConstIterator lit2 = att.multicastLocatorList.begin();
                    lit2!= att.multicastLocatorList.end();++lit2)
            {
                if(*lit1 == *lit2)
                {
                    missing = false;
                    break;
                }
            }
            if(missing)
            {
                logWarning(RTPS_READER,"Locator: "<< *lit1<< " not present in new list");
                logWarning(RTPS_READER,"Locator Lists cannot be changed or updated in this version");
            }
        }
    }

    //TOPIC ATTRIBUTES
    if(this->m_att.topic != att.topic)
    {
        logWarning(RTPS_READER,"Topic Attributes cannot be updated");
        updated &= false;
    }
    //QOS:
    //CHECK IF THE QOS CAN BE SET
    if(!this->m_att.qos.canQosBeUpdated(att.qos))
    {
        updated &=false;
    }
    if(updated)
    {
        this->m_att.expectsInlineQos = att.expectsInlineQos;
        if(this->m_att.qos.m_reliability.kind == RELIABLE_RELIABILITY_QOS)
        {
            //UPDATE TIMES:
            StatefulReader* sfr = (StatefulReader*)mp_reader;
            sfr->updateTimes(att.times);
        }
        this->m_att.qos.setQos(att.qos,false);
        //NOTIFY THE BUILTIN PROTOCOLS THAT THE READER HAS CHANGED
        mp_rtpsParticipant->updateReader(this->mp_reader, m_att.topic, m_att.qos);

        // Deadline

        if (m_att.qos.m_deadline.period != c_TimeInfinite)
        {
            deadline_duration_us_ =
                    duration<double, std::ratio<1, 1000000>>(m_att.qos.m_deadline.period.to_ns() * 1e-3);
            deadline_timer_.update_interval_millisec(m_att.qos.m_deadline.period.to_ns() * 1e-6);
        }
        else
        {
            deadline_timer_.cancel_timer();
        }

        // Lifespan

        if (m_att.qos.m_lifespan.duration != c_TimeInfinite)
        {
            lifespan_duration_us_ =
                    std::chrono::duration<double, std::ratio<1, 1000000>>(m_att.qos.m_lifespan.duration.to_ns() * 1e-3);
            lifespan_timer_.update_interval_millisec(m_att.qos.m_lifespan.duration.to_ns() * 1e-6);
        }
        else
        {
            lifespan_timer_.cancel_timer();
        }
    }

    return updated;
}

void SubscriberImpl::SubscriberReaderListener::onNewCacheChangeAdded(
        RTPSReader* /*reader*/,
        const CacheChange_t * const change_in)
{
    if (mp_subscriberImpl->onNewCacheChangeAdded(change_in))
    {
        if(mp_subscriberImpl->mp_listener != nullptr)
        {
            //cout << "FIRST BYTE: "<< (int)change->serializedPayload.data[0] << endl;
            mp_subscriberImpl->mp_listener->onNewDataMessage(mp_subscriberImpl->mp_userSubscriber);
        }
    }
}

void SubscriberImpl::SubscriberReaderListener::onReaderMatched(RTPSReader* /*reader*/, MatchingInfo& info)
{
    if (this->mp_subscriberImpl->mp_listener != nullptr)
    {
        mp_subscriberImpl->mp_listener->onSubscriptionMatched(mp_subscriberImpl->mp_userSubscriber,info);
    }
}

bool SubscriberImpl::onNewCacheChangeAdded(const CacheChange_t* const change_in)
{
    if (m_att.qos.m_deadline.period != c_TimeInfinite)
    {
        std::unique_lock<std::recursive_timed_mutex> lock(mp_reader->getMutex());

        if (!m_history.set_next_deadline(
                    change_in->instanceHandle,
                    steady_clock::now() + duration_cast<system_clock::duration>(deadline_duration_us_)))
        {
            logError(SUBSCRIBER, "Could not set next deadline in the history");
        }
        else if (timer_owner_ == change_in->instanceHandle || timer_owner_ == InstanceHandle_t())
        {
            deadline_timer_reschedule();
        }
    }

    CacheChange_t* change = (CacheChange_t*)change_in;

    if (m_att.qos.m_lifespan.duration == c_TimeInfinite)
    {
        return true;
    }

    auto source_timestamp = system_clock::time_point() + nanoseconds(change->sourceTimestamp.to_ns());
    auto now = system_clock::now();

    // The new change could have expired if it arrived too late
    // If so, remove it from the history and return false to avoid notifying the listener
    if (now - source_timestamp >= lifespan_duration_us_)
    {
        m_history.remove_change_sub(change);
        return false;
    }

    CacheChange_t* earliest_change;
    if (m_history.get_earliest_change(&earliest_change))
    {
        if (earliest_change == change)
        {
            // The new change has been added at the begining of the the history
            // As the history is sorted by timestamp, this means that the new change has the smallest timestamp
            // We have to stop the timer as this will be the next change to expire
            lifespan_timer_.cancel_timer();
        }
    }
    else
    {
        logError(SUBSCRIBER, "A change was added to history that could not be retrieved");
    }

    auto interval = source_timestamp - now + duration_cast<nanoseconds>(lifespan_duration_us_);

    // Update and restart the timer
    // If the timer is already running this will not have any effect
    lifespan_timer_.update_interval_millisec(interval.count() * 1e-6);
    lifespan_timer_.restart_timer();
    return true;
}

/*!
 * @brief Returns there is a clean state with all Publishers.
 * It occurs when the Subscriber received all samples sent by Publishers. In other words,
 * its WriterProxies are up to date.
 * @return There is a clean state with all Publishers.
 */
bool SubscriberImpl::isInCleanState() const
{
    return mp_reader->isInCleanState();
}

uint64_t SubscriberImpl::getUnreadCount() const
{
    return m_history.getUnreadCount();
}

void SubscriberImpl::deadline_timer_reschedule()
{
    assert(m_att.qos.m_deadline.period != c_TimeInfinite);

    std::unique_lock<std::recursive_timed_mutex> lock(mp_reader->getMutex());

    steady_clock::time_point next_deadline_us;
    if (!m_history.get_next_deadline(timer_owner_, next_deadline_us))
    {
        logError(SUBSCRIBER, "Could not get the next deadline from the history");
        return;
    }
    auto interval_ms = duration_cast<milliseconds>(next_deadline_us - steady_clock::now());

    deadline_timer_.cancel_timer();
    deadline_timer_.update_interval_millisec((double)interval_ms.count());
    deadline_timer_.restart_timer();
}

void SubscriberImpl::deadline_missed()
{
    assert(m_att.qos.m_deadline.period != c_TimeInfinite);

    std::unique_lock<std::recursive_timed_mutex> lock(mp_reader->getMutex());

    deadline_missed_status_.total_count++;
    deadline_missed_status_.total_count_change++;
    deadline_missed_status_.last_instance_handle = timer_owner_;
    mp_listener->on_requested_deadline_missed(mp_userSubscriber, deadline_missed_status_);
    deadline_missed_status_.total_count_change = 0;

    if (!m_history.set_next_deadline(
                timer_owner_,
                steady_clock::now() + duration_cast<system_clock::duration>(deadline_duration_us_)))
    {
        logError(SUBSCRIBER, "Could not set next deadline in the history");
        return;
    }
    deadline_timer_reschedule();
}


void SubscriberImpl::get_requested_deadline_missed_status(RequestedDeadlineMissedStatus& status)
{
    std::unique_lock<std::recursive_timed_mutex> lock(mp_reader->getMutex());

    status = deadline_missed_status_;
    deadline_missed_status_.total_count_change = 0;
}

void SubscriberImpl::lifespan_expired()
{
    std::unique_lock<std::recursive_timed_mutex> lock(mp_reader->getMutex());

    CacheChange_t* earliest_change;
    if (!m_history.get_earliest_change(&earliest_change))
    {
        return;
    }

    auto source_timestamp = system_clock::time_point() + nanoseconds(earliest_change->sourceTimestamp.to_ns());
    auto now = system_clock::now();

    // Check that the earliest change has expired (the change which started the timer could have been removed from the history)
    if (now - source_timestamp < lifespan_duration_us_)
    {
        auto interval = source_timestamp - now + lifespan_duration_us_;
        lifespan_timer_.update_interval_millisec((double)duration_cast<milliseconds>(interval).count());
        lifespan_timer_.restart_timer();
        return;
    }

    // The earliest change has expired
    m_history.remove_change_sub(earliest_change);

    // Set the timer for the next change if there is one
    if (!m_history.get_earliest_change(&earliest_change))
    {
        return;
    }

    // Calculate when the next change is due to expire and restart
    source_timestamp = system_clock::time_point() + nanoseconds(earliest_change->sourceTimestamp.to_ns());
    now = system_clock::now();
    auto interval = source_timestamp - now + lifespan_duration_us_;

    assert(interval.count() > 0);

    lifespan_timer_.update_interval_millisec((double)duration_cast<milliseconds>(interval).count());
    lifespan_timer_.restart_timer();
}

} /* namespace fastrtps */
} /* namespace eprosima */
