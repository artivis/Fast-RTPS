// Copyright 2020 Canonical ltd.
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

/*!
 * @file BuiltinLoggingType.h
 */
#ifndef _FASTDDS_RTPS_SECURITY_LOGGING_BUILTINLOGGINGTYPE_H_
#define _FASTDDS_RTPS_SECURITY_LOGGING_BUILTINLOGGINGTYPE_H_

#include <fastdds/rtps/common/Types.h>
#include <fastdds/rtps/common/Time_t.h>
#include <fastdds/rtps/security/logging/LoggingLevel.h>
#include <fastdds/rtps/security/logging/NameValuePair.h>

#include <map>

#if defined(_WIN32)
#if defined(EPROSIMA_USER_DLL_EXPORT)
#define eProsima_user_DllExport __declspec( dllexport )
#else
#define eProsima_user_DllExport
#endif
#else
#define eProsima_user_DllExport
#endif

#if defined(_WIN32)
#if defined(EPROSIMA_USER_DLL_EXPORT)
#if defined(BuiltinLoggingType_SOURCE)
#define BuiltinLoggingType_DllAPI __declspec( dllexport )
#else
#define BuiltinLoggingType_DllAPI __declspec( dllimport )
#endif // BuiltinLoggingType_SOURCE
#else
#define BuiltinLoggingType_DllAPI
#endif
#else
#define BuiltinLoggingType_DllAPI
#endif // _WIN32

namespace eprosima {
namespace fastcdr {
    class Cdr;
}
}

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

/**
 * @brief The BuiltinLoggingType struct
 *
 * @note Definition in DDS-Sec v1.1 9.6
 */
struct BuiltinLoggingType final
{
    /*!
     * @brief This function returns the maximum serialized size of an object
     * depending on the buffer alignment.
     * @param current_alignment Buffer alignment.
     * @return Maximum serialized size.
     */
    eProsima_user_DllExport static size_t getMaxCdrSerializedSize(size_t current_alignment = 0);

    /*!
     * @brief This function returns the serialized size of a data depending on the buffer alignment.
     * @param data Data which is calculated its serialized size.
     * @param current_alignment Buffer alignment.
     * @return Serialized size.
     */
    eProsima_user_DllExport static size_t getCdrSerializedSize(const BuiltinLoggingType& data, size_t current_alignment = 0);


    /*!
     * @brief This function serializes an object using CDR serialization.
     * @param cdr CDR serialization object.
     */
    eProsima_user_DllExport void serialize(eprosima::fastcdr::Cdr &cdr) const;

    /*!
     * @brief This function deserializes an object using CDR serialization.
     * @param cdr CDR serialization object.
     */
    eProsima_user_DllExport void deserialize(eprosima::fastcdr::Cdr &cdr);

    /*!
     * @brief This function returns the maximum serialized size of the Key of an object
     * depending on the buffer alignment.
     * @param current_alignment Buffer alignment.
     * @return Maximum serialized size.
     */
    eProsima_user_DllExport static size_t getKeyMaxCdrSerializedSize(size_t current_alignment = 0);

    /*!
     * @brief This function tells you if the Key has been defined for this type
     */
    eProsima_user_DllExport static bool isKeyDefined();

    /*!
     * @brief This function serializes the key members of an object using CDR serialization.
     * @param cdr CDR serialization object.
     */
    eProsima_user_DllExport void serializeKey(eprosima::fastcdr::Cdr &cdr) const;

    octet facility;           // Set to 0x0A (10). Indicates sec/auth msgs
    LoggingLevel severity;
    rtps::Time_t timestamp;   // Since epoch 1970-01-01 00:00:00 +0000 (UTC)
    std::string hostname;     // IP host name of originator
    std::string hostip;       // IP address of originator
    std::string appname;      // Identify the device or application
    std::string procid;       // Process name/ID for syslog system
    std::string msgid;        // Identify the type of message
    std::string message;      // Free-form message
    // Note that certain string keys (SD-IDs) are reserved by IANA
    std::map<std::string, NameValuePairSeq> structured_data;
};

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima

#endif // _FASTDDS_RTPS_SECURITY_LOGGING_BUILTINLOGGINGTYPE_H_
