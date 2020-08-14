#include <security/logging/LogTopic.h>

#include <fastdds/rtps/security/logging/BuiltinLoggingTypePubSubTypes.h>
#include <fastdds/rtps/history/WriterHistory.h>
#include <fastdds/rtps/writer/RTPSWriter.h>

#include <fastrtps/publisher/Publisher.h>
#include <fastrtps/log/Log.h>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

LogTopic::LogTopic()
    : stop_(false)
    , thread_([this]() {
                    for (;;)
                    {
                        // Put the thread asleep until there is
                        // something to process
                        auto p = queue_.wait_pop();

                        if (!p)
                        {
                            if (stop_)
                            {
                                return;
                            }
                            continue;
                        }

                        publish(*p);
                    }
                })
{
    //
}

LogTopic::~LogTopic()
{
    stop();
    queue_.push(BuiltinLoggingTypePtr(nullptr));
    if (thread_.joinable())
    {
        thread_.join();
    }

    if (file_stream_.is_open())
    {
        file_stream_.close();
    }
}

void LogTopic::log_impl(
        const BuiltinLoggingType& message,
        SecurityException& /*exception*/) const
{
    queue_.push(BuiltinLoggingTypePtr(new BuiltinLoggingType(message)));
}

bool LogTopic::enable_logging_impl(
        SecurityException& exception)
{
    LogOptions options;
    if (!get_log_options(options, exception))
    {
        return false;
    }

    if (!options.log_file.empty())
    {
        file_stream_.open(options.log_file, std::ios::out | std::ios::app);

        if ( (file_stream_.rdstate() & std::ofstream::failbit ) != 0 )
        {
            exception = SecurityException("Error opening file: " + options.log_file);
            return false;
        }
    }

    return true;
}

void LogTopic::publish(
        BuiltinLoggingType& builtin_msg)
{
    SecurityException exception;
    if (!file_stream_.is_open() || !compose_header(file_stream_, builtin_msg, exception))
    {
        return;
    }

    file_stream_ << " : " << builtin_msg.message << "\n";
    file_stream_.flush();

    if (writer_history_ && writer_)
    {
      if (writer_history_->isFull())
      {
        logWarning(SECURITY, "History full, cleaning up.");
        writer_history_->remove_all_changes();
      }

      CacheChange_t* ch = writer_->new_change(builtin_msg, ALIVE/*, h*/);

      if (!ch) // In the case history is full, remove some old changes
      {
        writer_->remove_older_changes(20);
        ch = writer_->new_change(builtin_msg, ALIVE);

        if (!ch) // In the case history is full, remove some old changes
        {
          logError(SECURITY, "Failed to create a security logging new change");
          return;
        }
      }

      if (!writer_type_->serialize((void*)&builtin_msg, &(ch->serializedPayload)))
      {
        logError(SECURITY, "Logging plugin Message serialization failed");
        writer_history_->release_Cache(ch);
        return;
      }

      if (!writer_history_->add_change(ch))
      {
        logError(SECURITY, "Logging plugin Message change update failed");
        writer_history_->release_Cache(ch);
      }
    }
}

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima
