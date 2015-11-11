using System.Text;
using System.Web.Script.Serialization;
using CCB.Data.Contracts;
using CCB.Model;
using CCB.Model.Documents;
using CCB.Model.Notifications;
using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using CCB.Data.Contracts.Repositories;
using CCB.Model.Security;
using CCB.Model.StageDB.Clients;

namespace CCB.Services
{
    public class NotificationService : BaseService
    {
        public NotificationService(IDataUow uow)
        {
            Contract.Requires(uow != null);
            Uow = uow;
        }


        internal class Placeholder
        {
            // Название
            public string Name { get; set; }

            // Тип данных
            public string DataType { get; set; }

            // Замена пустой строки
            public string EmptyString { get; set; }

            // Формат
            public string Format { get; set; }
        }

        public void SaveNotification(Notification notification)
        {
            if (notification.Recipients != null && notification.Recipients.All(r => r != null))
            {
                if (!notification.Recipients.Any() &&
                    !notification.RecipientUserType.HasValue)
                    return;
                //throw new ApplicationException("Нельзя отправить уведомление без адресата");

                if (!notification.RecipientUserType.HasValue)
                    if (notification.Recipients.Any(r => 
                                                        r != null && 
                                                        string.IsNullOrEmpty(r.Email) &&                                                        
                                                        (!r.UserId.HasValue && r.User == null)))
                        return;
                //throw new ApplicationException("Нельзя указывать адресата без ссылки на пользователя и пустым адресом email");

                Uow.Save<Notification, IRepository<Notification>>(notification);
            }
        }

        public IEnumerable<NotificationSendLogRow> GetNotificationSendTries(Guid notificationId, NotificationMessageTemplateTypeDictionary? sendType = null, SendStatusDictionary sendStatus = SendStatusDictionary.NeedToSend)
        {
            return Uow.NotificationSendLog.GetByNotificationId(notificationId,
                                                               sendType,
                                                               sendStatus);
        }

        public Guid SaveNotificationSendLogRow(NotificationSendLogRow sendLogRow)
        {
            return Uow.Save<NotificationSendLogRow, IRepository<NotificationSendLogRow>>(sendLogRow);
        }

        public IEnumerable<Notification> GetNotificationsForCompose(int HeapSize)
        {
            return Uow.Notifications.GetNotificationsForCompose(HeapSize);
        }

        public NotificationMessageTemplateTypeDictionary GetNotificationMessageTypes(Notification notification)
        {
            if (notification.LastSendTryGroupId == null)
                return notification.ExpectedMessageTemplateTypes;

            return Uow.NotificationSendLog.GetMessageTypes(notification.Id, notification.LastSendTryGroupId.Value)
                    .Aggregate<NotificationMessageTemplateTypeDictionary, NotificationMessageTemplateTypeDictionary>
                    (0, (current, messageType) => current & messageType);
        }

        public NotificationMessageTemplate GetActiveNotificationMessageTemplateBytype(Guid notificationTemplateId, NotificationMessageTemplateTypeDictionary messageTemplateType)
        {
            return Uow.NotificationMessageTemplates.GetActiveNotificationMessageTemplateBytype(notificationTemplateId, messageTemplateType);
        }

        public IEnumerable<NotificationSendLogRow> GetNotificationMessagesNeedtoSendByType(NotificationMessageTemplateTypeDictionary type, int heapSize)
        {
            return Uow.NotificationSendLog.GetNeedtoSendByType(type, heapSize);
        }

        public NotificationTemplate GetNotificationTemplate(NotificationTypeDictionary notificationType)
        {
            return Uow.NotificationTemplates.GetByType(notificationType);
        }

        public bool needToCompose(Guid notificationId, Guid recipientId, NotificationMessageTemplateTypeDictionary expectedMessageType)
        {
            return Uow.NotificationSendLog.NeedToCompose(notificationId, recipientId, expectedMessageType);
        }

        public bool needToLogComposeError(Guid notificationId, Guid recipientId, NotificationMessageTemplateTypeDictionary expectedMessageType)
        {
            return Uow.NotificationSendLog.NeedToLogComposeError(notificationId, recipientId, expectedMessageType);
        }

        public NotificationSendLogRow GetNotificationSendLogRow(Guid notificationSendLogRowId)
        {
            return Uow.NotificationSendLog.GetById(notificationSendLogRowId);
        }

        public Notification GetNotification(Guid notificationId)
        {
            return Uow.Notifications.GetById(notificationId);
        }

        public IEnumerable<DocumentProcessEventSubscribe> GetAllSubscriptionsForClient(int clientId)
        {
            return Uow.DocumentProcessEventSubscribes.GetAllSubscriptionsForClient(clientId);
        }

        public NotificationSendLogRow CreateNotificationMessage(Notification notification,
                                                                 string composedContent,
                                                                 string composedSubject,
                                                                 NotificationRecipient rec,
                                                                 NotificationMessageTemplateTypeDictionary notificationMessageTemplateType,
                                                                 Guid tryGroupId)
        {
            var status = SendStatusDictionary.ErrorOnCompose;
            string sendedSubject = "";
            string sendedContent = "";

            if (composedContent != null && composedSubject != null)
            {
                status = SendStatusDictionary.NeedToSend;
                sendedSubject = composedSubject;
                sendedContent = composedContent;
            }

            var rez = new NotificationSendLogRow
            {
                Notification = notification,
                Recipient = rec,
                SendDateTime = DateTime.Now,
                SendTryGroupId = tryGroupId,
                SendType = notificationMessageTemplateType,
                SendStatus = status,
                SendedSubject = sendedSubject,
                SendedContent = sendedContent,
            };
            return rez;
        }

        public string HtmlTemplateCompose(string template, IDictionary<string, string> data)
        {
            // Если в итоге шаблон пуст, возвращаем пустую строку - отображать нам нечего, но пустая строка по крайней мере в большинстве случаев ничего не испортит.
            if (String.IsNullOrEmpty(template))
            {
                return string.Empty;
            }

            // Обработаем контекстные токены
            template = ContextTokens.Process(template);

            #region Вставка данных из словаря

            // Обработаем токены полей
            var serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = int.MaxValue;
            var parts = template.Split(new[] { "|" }, StringSplitOptions.None);

            var result = new StringBuilder();

            foreach (var part in parts)
            {
                try
                {
                    var decodedPart = part.Replace("&quot;", "\"");
                    var placeholder = serializer.Deserialize<Placeholder>(decodedPart);
                    // Ищем значение в словарике, а если его там нет - в элементе списка
                    string resultValue = null;

                    if (data != null && data.ContainsKey(placeholder.Name))
                    {
                        resultValue = data[placeholder.Name];

                        if (!string.IsNullOrEmpty(placeholder.EmptyString) && string.IsNullOrEmpty(resultValue))
                            resultValue = placeholder.EmptyString;

                        if (!string.IsNullOrEmpty(placeholder.DataType))
                        {
                            DateTime date;
                            string dateTimeFormat;
                            switch (placeholder.DataType)
                            {
                                case "Date":
                                    date = DateTime.Parse(resultValue);
                                    dateTimeFormat = string.IsNullOrEmpty(placeholder.Format)
                                        ? "dd.MM.yyyy"
                                        : placeholder.Format;
                                    resultValue = date.ToString(dateTimeFormat);
                                    break;
                                case "DateTime":
                                    date = DateTime.Parse(resultValue);
                                    dateTimeFormat = string.IsNullOrEmpty(placeholder.Format)
                                        ? "dd.MM.yyyy HH:mm:ss"
                                        : placeholder.Format;
                                    resultValue = date.ToString(dateTimeFormat);
                                    break;
                                case "integer":
                                    var intValue = int.Parse(resultValue);
                                    resultValue = string.IsNullOrEmpty(placeholder.Format)
                                        ? intValue.ToString()
                                        : intValue.ToString(placeholder.Format);
                                    break;
                                case "double":
                                    var doubleValue = double.Parse(resultValue);
                                    resultValue = string.IsNullOrEmpty(placeholder.Format)
                                        ? doubleValue.ToString()
                                        : doubleValue.ToString(placeholder.Format);
                                    break;
                                case "float":
                                    var floratValue = int.Parse(resultValue);
                                    resultValue = string.IsNullOrEmpty(placeholder.Format)
                                        ? floratValue.ToString()
                                        : floratValue.ToString(placeholder.Format);
                                    break;
                                default:
                                    break;
                            }
                        }
                    }

                    result.Append(resultValue);
                }
                catch
                {
                    if (data != null && data.ContainsKey(part))
                    {
                        result.Append(data[part]);
                    }
                    else
                    {
                        // Если мы получили ошибку, 
                        // значит возникли проблемы с парсингом токена. 
                        // Либо токен написан неправильно, либо его в этой части вообще нет, 
                        // поэтому просто выводим входные данные
                        result.Append(part);
                    }
                }
            }

            #endregion

            return result.ToString();
        }

        public string JsonDtoCompose(NotificationTypeDictionary notificationType, Dictionary<string, string> data)
        {
            var createdTasksTypes = new[]
                                        {
                                                NotificationTypeDictionary.TaskCreated,
                                                NotificationTypeDictionary.TaskCreateDocCreated,
                                                NotificationTypeDictionary.TaskVisaCreated,
                                                NotificationTypeDictionary.TaskManualExecute
                                        };


            if (createdTasksTypes.Contains(notificationType))
            {

                var newTaskNotification = new NewItemsNotification
                {
                    Ids = new[] { data["TaskId"] },
                    Type = NewItemsNotificationType.Task
                }; 
                
                var serializer = new JavaScriptSerializer();
                serializer.MaxJsonLength = int.MaxValue;
                string message = serializer.Serialize(newTaskNotification);
                var notificationData = new ClientNotification { Message = message, NotificationType = ClientNotificationType.NewItems };
                return serializer.Serialize(notificationData);
            }

            return string.Empty;
        }

        public Notification CreateNotification(Authority authority)
        {
            var notification = new Notification
            {
                Created = DateTime.Now,
                ExpectedMessageTemplateTypes = NotificationMessageTemplateTypeDictionary.Email |
                                               NotificationMessageTemplateTypeDictionary.Sms |
                                               NotificationMessageTemplateTypeDictionary.Web,
            };

            List<NotificationDataRow> notificationData = GetNotificationData(authority)
                                                                  .Select(pair => new NotificationDataRow
                                                                                  {
                                                                                          Id = Guid.NewGuid(),
                                                                                          Key = pair.Key,
                                                                                          Data = pair.Value
                                                                                  })
                                                                  .ToList();

            notification.Data = notificationData;
            notification.NotificationStatus = NotificationStatusDictionary.CreateSendtries;
            return notification;
        }

        public Dictionary<string, string> GetNotificationData(Authority authority)
        {
            Dictionary<string, string> res = new Dictionary<string, string>();
            res["AuthorityEndDate"] = authority.EndDate.Value.ToString(Consts.DateTimeFormat);
            return res;
        }


        public Notification CreateNotification(Certificate certificate)
        {
            var notification = new Notification
            {
                Created = DateTime.Now,
                ExpectedMessageTemplateTypes = NotificationMessageTemplateTypeDictionary.Email |
                                               NotificationMessageTemplateTypeDictionary.Sms |
                                               NotificationMessageTemplateTypeDictionary.Web,
            };

            List<NotificationDataRow> notificationData = certificate.GetNotificationData()
                                                                    .Select(pair => new NotificationDataRow
                                                                                  {
                                                                                          Id = Guid.NewGuid(),
                                                                                          Key = pair.Key,
                                                                                          Data = pair.Value
                                                                                  })
                                                                    .ToList();

            notification.Data = notificationData;
            notification.NotificationStatus = NotificationStatusDictionary.CreateSendtries;
            return notification;
        }
    }

    internal static class ContextTokens
    {
        public static string Process(string source)
        {
            if (source == null)
                return null;

            // Получим список токенов и значений
            #region Список токенов и значений
            var tokens = new List<ContextToken>();

            // Текущая дата
            var now = DateTime.Now;
            tokens.AddToken(TodayDay, now.Day);
            tokens.AddToken(TodayMonth, now.Month);
            tokens.AddToken(TodayYear, now.Year);
            tokens.AddToken(Today, now);

            #endregion

            // Заменим в строке идентификаторы токенов на порядковые номера в списке
            foreach (var token in tokens.OrderByDescending(t => t.Key.Length))
            {
                source = source.Replace(token.Key, token.Value);
            }

            return source;
        }

        private const string Today = "TODAY";
        private const string TodayDay = "TODAYDAY";
        private const string TodayMonth = "TODAYMONTH";
        private const string TodayYear = "TODAYYEAR";

        public static void AddToken(this List<ContextToken> tokens, string key, object value)
        {
            tokens.Add(new ContextToken { Key = String.Format("{0}", key).ToUpper(), Value = value != null ? value.ToString() : String.Empty });
        }

        public class ContextToken
        {
            public string Key { get; set; }
            public string Value { get; set; }
        }

    }

}