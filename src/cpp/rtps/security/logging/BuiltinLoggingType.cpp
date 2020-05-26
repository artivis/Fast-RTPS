#include <fastdds/rtps/security/logging/BuiltinLoggingType.h>
#include <fastcdr/Cdr.h>
#include <fastcdr/exceptions/BadParamException.h>

#include <utility>

#ifdef _WIN32
// Remove linker warning LNK4221 on Visual Studio
namespace { char dummy; }
#endif

//using namespace eprosima::fastcdr::exception;

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

size_t BuiltinLoggingType::getMaxCdrSerializedSize(size_t current_alignment)
{
    size_t initial_alignment = current_alignment;

    current_alignment += 1 + eprosima::fastcdr::Cdr::alignment(current_alignment, 1);

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4);

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4);

    for(size_t a = 0; a < 100; ++a)
    {
        current_alignment += 1 + eprosima::fastcdr::Cdr::alignment(current_alignment, 1);

        for(size_t b = 0; b < 100; ++b)
        {
            current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;
            current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;
        }
        // @todo(artivis) not sure if this should be in the loop too
        current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4);
    }

    return current_alignment - initial_alignment;
}

size_t BuiltinLoggingType::getCdrSerializedSize(const BuiltinLoggingType& data, size_t current_alignment)
{
    size_t initial_alignment = current_alignment;

    current_alignment += 1 + eprosima::fastcdr::Cdr::alignment(current_alignment, 1);

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4);

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + data.hostname.size() + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + data.hostip.size() + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + data.appname.size() + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + data.procid.size() + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + data.msgid.size() + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + data.message.size() + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4);

    for(const auto& p : data.structured_data)
    {
        current_alignment += 1 + eprosima::fastcdr::Cdr::alignment(current_alignment, 1);

        for(const auto& s : p.second)
        {
          current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + s.name.size() + 1;
          current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + s.value.size() + 1;
        }
        // @todo(artivis) not sure if this should be in the loop too
        current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4);
    }

    return current_alignment - initial_alignment;
}

void BuiltinLoggingType::serialize(eprosima::fastcdr::Cdr &scdr) const
{
    scdr << facility;
    scdr << static_cast<std::underlying_type<LoggingLevel>::type>(severity);
    scdr << hostname;
    scdr << hostip;
    scdr << appname;
    scdr << procid;
    scdr << msgid;
    scdr << message;
    scdr << structured_data;
}

void BuiltinLoggingType::deserialize(eprosima::fastcdr::Cdr &dcdr)
{
    dcdr >> facility;
    {
        std::underlying_type<LoggingLevel>::type enum_value = 0;
        dcdr >> enum_value;
        severity = static_cast<LoggingLevel>(enum_value);
    }
    dcdr >> hostname;
    dcdr >> hostip;
    dcdr >> appname;
    dcdr >> procid;
    dcdr >> msgid;
    dcdr >> message;
    dcdr >> structured_data;
}

size_t BuiltinLoggingType::getKeyMaxCdrSerializedSize(size_t current_alignment)
{
    size_t current_align = current_alignment;

    return current_align;
}

bool BuiltinLoggingType::isKeyDefined()
{
   return false;
}

void BuiltinLoggingType::serializeKey(eprosima::fastcdr::Cdr &scdr) const
{
    (void) scdr;
}

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima
