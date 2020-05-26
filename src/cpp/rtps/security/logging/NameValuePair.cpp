#include <fastdds/rtps/security/logging/NameValuePair.h>
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

size_t NameValuePair::getMaxCdrSerializedSize(size_t current_alignment)
{
    size_t initial_alignment = current_alignment;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + 255 + 1;

    return current_alignment - initial_alignment;
}

size_t NameValuePair::getCdrSerializedSize(const NameValuePair& data, size_t current_alignment)
{
    (void)data;
    size_t initial_alignment = current_alignment;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + data.name.size() + 1;

    current_alignment += 4 + eprosima::fastcdr::Cdr::alignment(current_alignment, 4) + data.value.size() + 1;

    return current_alignment - initial_alignment;
}

void NameValuePair::serialize(eprosima::fastcdr::Cdr &scdr) const
{
    scdr << name;
    scdr << value;
}

void NameValuePair::deserialize(eprosima::fastcdr::Cdr &dcdr)
{
    dcdr >> name;
    dcdr >> value;
}

size_t NameValuePair::getKeyMaxCdrSerializedSize(size_t current_alignment)
{
    size_t current_align = current_alignment;

    return current_align;
}

bool NameValuePair::isKeyDefined()
{
   return false;
}

void NameValuePair::serializeKey(eprosima::fastcdr::Cdr &scdr) const
{
    (void) scdr;
}

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima
