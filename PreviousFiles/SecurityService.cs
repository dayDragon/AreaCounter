using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CCB.Data.Contracts;
using CCB.Data.Contracts.Repositories;
using CCB.Model;
using CCB.Model.Calendars;
using CCB.Model.Clients;
using CCB.Model.Documents;
using CCB.Model.Log;
using CCB.Model.Notifications;
using CCB.Model.Security;
using CCB.Model.Settings;
using CCB.Model.StageDB.Clients;
using CCB.Model.StageDB.Documents;
using Ninject;
using NLog;

namespace CCB.Services
{
    public class SecurityService : BaseService
    {
        private readonly Logger log;

        /// <summary>
        ///     Конструктор по умолчанию
        /// </summary>
        /// <param name="uow">Контекст работы с СУБД</param>
        public SecurityService(IDataUow uow)
        {
            Uow = uow;
            log = LogManager.GetLogger("audit");
        }

        public EqualityComparerIPRange IPRangeEqualityComparer
        {
            get { return new EqualityComparerIPRange(); }
        }

        /// <summary>
        ///     Создание записи аудита об операции в ЛКК
        /// </summary>
        /// <param name="operationType">Тип операции из справочника</param>
        /// <param name="auditThreadId">Идентификатор корневой операции аудита</param>
        /// <param name="userId">Идентификатор пользователя, проводившего операцию</param>
        /// <param name="sessionId">Идентификатор сессии</param>
        /// <param name="client"></param>
        /// <param name="accessGranted"></param>
        /// <param name="operationInfo">Дополнительная информация об операции</param>
        /// <param name="auditInfo">Массив дополнительной информации об операции в виде ключ - значение</param>
        /// <param name="documentId">Идентификатор документа, если операция отностится к документу</param>
        private void AuditOperation(AuditOperationTypeDictionary operationType,
                                   Guid auditThreadId,
                                   Guid userId,
                                   Guid sessionId,
                                   int? client = null,
                                   bool accessGranted = true,
                                   string operationInfo = null,
                                   Dictionary<string, string> auditInfo = null,
                                   Guid? documentId = null)
        {
            int auditRowNumber = Uow.GetNextCounterValue(CounterTypeDictionary.AuditRowNumberCounter);

            var auditOperation = new AuditRow
                                 {
                                         Id = Guid.NewGuid(),
                                         RowNumber = auditRowNumber,
                                         CorrelationId = auditThreadId,
                                         OperationType = operationType,
                                         UserId = userId,
                                         SessionId = sessionId,
                                         Client = client,
                                         OperationInfo = operationInfo,
                                         OperationDateTime = DateTime.Now,
                                         AccessGranted = accessGranted,
                                         DocumentMetadataId = documentId,
                                         AuditInfoRows = auditInfo == null
                                                                 ? null
                                                                 : auditInfo.Select(i => new AuditInfoRow
                                                                                         {
                                                                                                 Id = Guid.NewGuid(),
                                                                                                 //InfoKey = i.Key,
                                                                                                 Info = i.Value
                                                                                         })
                                                                            .ToList()
                                 };

            Uow.Audit.Add(auditOperation);
            Uow.Commit();

            User user = GetUser(userId);

            //LogAudit(auditOperation.OperationDateTime, session, clientName, actionType, auditObject, accessGranted, comment);
            log.Info(new AuditPlainRow
                     {
                             EventID = auditRowNumber.ToString(),
                             Time = auditOperation.OperationDateTime,
                             User = user.GetFullName(),
                             Host = string.Empty,
                             Source = user.Session.ClientIpAddress,
                             Destination = string.Empty,
                             EntryType = operationType.ToString(),
                             Message = operationInfo,
                             DocumentInfo = GetDocumentInfo(documentId)
                     }.ToString());
        }

        private string GetDocumentInfo(Guid? documentId)
        {
            string documentInfo = null;
            if (documentId.HasValue)
            {
                var document = Uow.DocumentsMetadata.GetById(documentId.Value);
                documentInfo = string.Format("{0} № {1}",
                                             document.DocumentType != null
                                                     ? document.DocumentType.Name
                                                     : Uow.DocumentTypes.GetByTypeId(document.DocumentTypeId)
                                                          .Name,
                                             document.BankDocumentNumber);
            }
            return documentInfo;
        }

        public void AddSession(Session session)
        {
            Uow.Sessions.Add(session);
            Uow.Users.Update(session.User);
            Uow.Commit();
        }

        public Guid? PutSessionToSessionLogAndDelete(Guid userId)
        {
            Session session = Uow.Sessions.GetUserSession(userId);

            if (session == null)
                return null;

            var sessionLogRow = new SessionLogRow
                                {
                                        Id = session.Id,
                                        Opened = session.Opened,
                                        Closed = DateTime.Now,
                                        User = session.User,
                                        UserId = session.User.Id,
                                        ClientIpAddress = session.ClientIpAddress
                                };

            sessionLogRow.User.SessionLogRows.Add(sessionLogRow);
            sessionLogRow.User.Session = null;
            Uow.Users.Update(sessionLogRow.User);
            Uow.SessionsLog.Add(sessionLogRow);
            Uow.Sessions.Delete(session);
            return sessionLogRow.Id;
        }

        public User GetUserByLogin(string login)
        {
            return Uow.Users.GetByLogin(login);
        }


        /// <summary>
        ///     Закрытие сессии
        /// </summary>
        /// <param name="sessionId"></param>
        public void CloseSession(Guid sessionId)
        {
            Session session = Uow.Sessions.GetById(sessionId);

            var sessionLogRow = new SessionLogRow
                                {
                                        Id = session.Id,
                                        Opened = session.Opened,
                                        Closed = DateTime.Now,
                                        User = session.User,
                                        UserId = session.User.Id
                                };

            sessionLogRow.User.SessionLogRows.Add(sessionLogRow);
            sessionLogRow.User.Session = null;
            Uow.Users.Update(sessionLogRow.User);
            Uow.SessionsLog.Add(sessionLogRow);
            Uow.Sessions.Delete(session);
        }

        /// <summary>
        ///     Обновление времени последней активности сессии
        /// </summary>
        /// <param name="sessionId">Идентификатор сессии пользователя</param>
        public void UpdateSessionLastActivity(Guid sessionId)
        {
            Session session = Uow.Sessions.GetById(sessionId);
            session.LastActivity = DateTime.Now;
            Uow.Sessions.Update(session);
            Uow.Commit();
        }

        /// <summary>
        ///     Обновление данных пользователя
        /// </summary>
        /// <param name="user">Данные пользователя</param>
        public void SaveUser(User user,
                             bool autoCommit)
        {
            Uow.Save<User, IRepository<User>>(user,
                                              autoCommit);
        }

        /// <summary>
        ///     Получение сессии пользователя по ее идентификатору
        /// </summary>
        /// <param name="sessionId">Идентификатор сессии</param>
        /// <returns>Сессия, если не найдена то null</returns>
        public Session GetSessionById(Guid sessionId)
        {
            return Uow.Sessions.GetById(sessionId);
        }

        public bool CheckUserPermissionToReadDocument(Guid documentId,
                                                      Guid userId,
                                                      int? clientId)
        {
            var rez = Uow.Permissions.CheckUserPermission(PermissionIdDictionary.Documents_ReadAllClientDocuments,
                                                       userId,
                                                       clientId,
                                                       Uow.DocumentsMetadata.GetDocumentType(documentId)) ||
                   (Uow.DocumentsMetadata.GetThreadByDocId(documentId,false).Select(d=>d.AuthorUserId).Contains(userId) &&
                        Uow.Permissions.CheckUserPermission(PermissionIdDictionary.Documents_ReadOnlyCreatedByUserClientDocumentsAndAnswers,
                                                            userId,
                                                            clientId,
                                                            Uow.DocumentsMetadata.GetDocumentType(documentId)));
            if(rez) return true;
            var user = Uow.Users.GetById(userId);
            var docIds = Uow.DocumentsMetadata.GetThreadByDocId(documentId,false).Select(d=>d.DocumentMetadataId);
            foreach (var docId in docIds)
            {
                var tasks = Uow.DocumentProcessTasks.GetDocumentProcessTasksByDocumentId(docId);
                foreach (var task in tasks)
                {
                    var userIds = new List<Guid>();
                    if (task.ResponsibleUserGroupId != null)
                        userIds = Uow.Users.GetByGroupId(task.ResponsibleUserGroupId.Value).Select(u=>u.Id).ToList();
                    if(task.ExecutorId == userId || userIds.Contains(userId)||user.UserType == task.ResponcibleUserType)
                        return true;
                }
            }

            return false;
        }

        public IList<Permission> GetPermissionsForUser(Guid currentUserId,
                                                       int? clientId,
                                                       IEnumerable<DocumentBusinessDivisionDictionary> businessDivisions = null)
        {
            if (businessDivisions == null)
                return Uow.Permissions.GetPermissionsForUser(currentUserId,
                                                             clientId);

            return Uow.Permissions.GetPermissionsForUser(currentUserId,
                                                         clientId,
                                                         businessDivisions);
        }

        public IList<Permission> GetOnlyUserPermissions(Guid currentUserId,
                                                        int? clientId)
        {
            return Uow.Permissions.GetOnlyUserPermissions(currentUserId,
                                                          clientId);
        }

        public Certificate GetActiveCertificate(Guid userId)
        {
            return Uow.Certificates.GetActiveForUser(userId);
        }

        public Guid? GetUserIdBySessionId(Guid sessionId)
        {
            Session session = Uow.Sessions.GetById(sessionId);
            return session == null
                           ? null
                           : (Guid?) session.User.Id;
        }

        public void Commit()
        {
            Uow.Commit();
        }

        public IEnumerable<User> GetUsersById(IEnumerable<Guid> userIds)
        {
            return Uow.Users.GetUsersById(userIds);
        }

        public IEnumerable<Role> GetRolesByIds(IEnumerable<Guid> roleIds)
        {
            return Uow.Roles.GetRolesByIds(roleIds);
        }

        public IEnumerable<UserGroup> GetUsersGroupsByIds(IEnumerable<Guid> groupIds)
        {
            return Uow.UserGroups.GetUsersGroupsByIds(groupIds);
        }

        public IEnumerable<UserGroup> GetUsersGroupsByUserId(Guid userId)
        {
            return Uow.UserGroups.GetUsersGroupsByUserId(userId);
        }

        public IEnumerable<CertificateRequest> GetUserCertificateRequests(Guid userId)
        {
            return Uow.CertificateRequests.GetUserCertificateRequests(userId);
        }

        public IEnumerable<Certificate> GetUserCertificates(Guid userId)
        {
            return Uow.Certificates.GetUserCertificates(userId);
        }

        public IEnumerable<Permission> GetPermissionsForRole(Guid roleId)
        {
            return Uow.Permissions.GetPermissionsForRole(roleId);
        }

        public UserTypeDictionary GetUserType(Guid userId)
        {
            return Uow.Users.GetUserType(userId);
        }

        public IEnumerable<User> GetUsersByType(UserTypeDictionary? userType)
        {
            return Uow.Users.GetUsersByType(userType);
        }

        public IEnumerable<User> GetByGroupId(Guid groupId)
        {
            return Uow.Users.GetByGroupId(groupId);
        }

        public void CreateUow()
        {
            Uow = IocKernel.IocKernelInstance.Get<IDataUow>();
        }

        public IEnumerable<Guid> GetUsersIdsByType(UserTypeDictionary userType)
        {
            return Uow.Users.GetUsersIdsByType(userType);
        }

        public IEnumerable<Session> GetSessions(TimeSpan notificationTime,                                                
                                                UserTypeDictionary userType, bool includeUsers = false)
        {
            return Uow.Sessions.GetSessions(notificationTime,
                                            userType,
                                            includeUsers);
        }

        public ICollection<Permission> GetRolePermissions(Guid roleId)
        {
            return Uow.Permissions.GetPermissionsForRole(roleId)
                      .ToList();
        }

        public bool UserHasOpenSession(Guid userId)
        {
            return Uow.Sessions.UserHasOpenSession(userId);
        }

        public Session GetUserSession(Guid userId)
        {
            return Uow.Sessions.GetUserSession(userId);
        }

        public void SaveSession(Session session)
        {
            if (session.Id == Guid.Empty)
                session.Id = Guid.NewGuid();

            if (!Uow.Sessions.IsExist(session.Id))
                Uow.Sessions.Add(session);
            else
                Uow.Sessions.Update(session);

            Uow.Commit();
        }

        /// <summary>Добавление пароля</summary>
        public Password GetUserCurrentPassword(Guid userId)
        {
            return Uow.Passwords.GetUserCurrentPassword(userId);
        }

        /// <summary>Получение типа пароля</summary>
        public PasswordTypeDictionary GetUserCurrentPasswordType(Guid userId)
        {
            return Uow.Passwords.GetUserCurrentPasswordType(userId);
        }

        /// <summary>Добавление пароля</summary>
        public void SavePassword(Password password,
                                 bool autoCommit)
        {
            password.Id = Guid.NewGuid();
            Uow.Passwords.Add(password);
            if (autoCommit)
                Uow.Commit();
        }

        /// <summary>
        ///     Проверка доступа пользователя с указанного IP адреса
        /// </summary>
        /// <param name="userId">Идентификатор пользователя</param>
        /// <param name="IP">IP адрес для проверки</param>
        /// <returns></returns>
        public bool IsUserAllowedToConnectFromIP(Guid userId,
                                                 string IP)
        {
            IEnumerable<IPRange> ipRanges = Uow.IPRanges.GetUserIPRanges(userId);
            if (ipRanges == null || !ipRanges.Any())
                return true;
            var ipList = new IPList();
            foreach (IPRange ipRange in ipRanges)
            {
                if (!string.IsNullOrEmpty(ipRange.Mask))
                    ipList.Add(ipRange.IP,
                               ipRange.Mask);
                else
                    ipList.Add(ipRange.IP);
            }

            return ipList.CheckNumber(IP);
        }

        public IEnumerable<IPRange> GetUserIPRanges(Guid userId)
        {
            return Uow.IPRanges.GetUserIPRanges(userId);
        }

        public void RemoveUserAllowedIPRangesToAccess(IEnumerable<IPRange> rangesToDelete,
                                                      bool isAutoCommitEnabled = true)
        {
            foreach (IPRange ipRange in rangesToDelete)
            {
                Uow.IPRanges.Delete(ipRange);
            }
            if (isAutoCommitEnabled)
                Uow.Commit();
        }

        public void AddUserAllowedIPRangesToAccess(IEnumerable<IPRange> rangesToAdd,
                                                   bool isAutoCommitEnabled = true)
        {
            foreach (IPRange ipRange in rangesToAdd)
            {
                Uow.IPRanges.Add(ipRange);
            }
            if (isAutoCommitEnabled)
                Uow.Commit();
        }

        #region Permissions

        /// <summary>
        ///     Получение списка прав доступа
        /// </summary>
        /// <returns>Массив прав доступа</returns>
        public ICollection<Permission> GetPermissions()
        {
            return Uow.Permissions.GetAll(true)
                      .ToList();
        }

        public bool CheckUserPermission(Guid? userId,
                                        PermissionIdDictionary permissionId,
                                        int? clientId = null,
                                        DocumentTypeDictionary? type = null)
        {
            if (userId == null)
                return false;
            return Uow.Permissions.CheckUserPermission(permissionId,
                                                       userId.Value,
                                                       clientId,
                                                       type);
        }

        /// <summary>
        ///     Проверка наличия права у пользователя читать документы
        /// </summary>
        /// <param name="userId">Идентификатор пользователя</param>
        /// <param name="clientId">Идентификатор Клиента из промежуточной БД</param>
        /// <param name="documentType">Тип документа</param>
        /// <returns>true - есть право, false - нет</returns>
        public bool CheckUserPermissionToReadDocuments(Guid userId,
                                                       int? clientId = null,
                                                       DocumentTypeDictionary? documentType = null)
        {
            bool accessGranted = CheckUserPermission(
                                                     userId,
                                                     PermissionIdDictionary.Documents_ReadAllClientDocuments,
                                                     clientId,
                                                     documentType);
            if (!accessGranted)
            {
                accessGranted = CheckUserPermission(
                                                    userId,
                                                    PermissionIdDictionary.Documents_ReadOnlyCreatedByUserClientDocumentsAndAnswers,
                                                    clientId,
                                                    documentType);
                if (!accessGranted)
                {
                    accessGranted = CheckUserPermission(
                                                        userId,
                                                        PermissionIdDictionary.Documents_ReadOnlyCreatedByUserClientDocuments,
                                                        clientId,
                                                        documentType);
                }
            }

            return accessGranted;
        }

        /// <summary>
        ///     Проверка наличия права у пользователя создавать документы
        /// </summary>
        /// <param name="userId">Идентификатор пользователя</param>
        /// <param name="clientId">Идентификатор Клиента из промежуточной БД</param>
        /// <param name="documentType">Тип документа</param>
        /// <returns>true - есть право, false - нет</returns>
        public bool CheckUserPermissionToCreateDocument(Guid userId,
                                                        int? clientId = null,
                                                        DocumentTypeDictionary? documentType = null)
        {
            bool accessGranted = CheckUserPermission(
                                                     userId,
                                                     PermissionIdDictionary.Documents_CreateDocument,
                                                     clientId,
                                                     documentType);
            if (!accessGranted)
            {
                accessGranted = CheckUserPermission(
                                                    userId,
                                                    PermissionIdDictionary.Documents_CreateDocument,
                                                    clientId,
                                                    documentType);
            }

            return accessGranted;
        }

        public void DeletePermissions(IEnumerable<Permission> freePermissions)
        {
            foreach (Permission permission in freePermissions)
            {
                Uow.Permissions.Delete(permission);
            }

            Uow.Commit();
        }

        #endregion Permissions

        #region AuditInfos

        /// <summary>
        ///     Сохранение в журнале операций отказ в доступе для пользователя
        /// </summary>
        /// <param name="sessionId">Идентификатор сессии</param>
        /// <param name="operationType">Тип операции</param>
        /// <param name="auditThreadId">Идентификатор корневой операции аудита</param>
        /// <param name="client"></param>
        /// <param name="operationInfo">Дополнительная информация об операции</param>
        /// <param name="userId">Идентификатор пользователя</param>
        public void AuditDeniedAccessToOperation(Guid userId,
                                                 Guid sessionId,
                                                 AuditOperationTypeDictionary operationType,
                                                 Guid auditThreadId,
                                                 int? client,
                                                 string operationInfo = null)
        {
            AuditOperation(operationType,
                           auditThreadId,
                           userId,
                           sessionId,
                           client,
                           false,
                           operationInfo);
        }

        #endregion AuditInfos

        #region Users

        /// <summary>
        ///     Получение списка пользователей
        /// </summary>
        /// <returns>Список пользователей</returns>
        public IEnumerable<User> GetAllUsers()
        {
            return Uow.Users.GetAll()
                      .ToList();
        }

        /// <summary>
        ///     Чтение данных пользователя с правами, группами и ролями
        /// </summary>
        /// <param name="userId">Идентификатор запрашиваемого пользователя</param>
        /// <returns>Пользователь с правами, группами и ролями</returns>
        public User GetUser(Guid userId)
        {
            return Uow.Users.GetById(userId);
        }

        #endregion Users

        #region Roles

        /// <summary>
        ///     Чтение полных данных о роли безопасности
        /// </summary>
        /// <param name="roleId">Идентификатор роли</param>
        /// <returns>Роль безопастности</returns>
        public Role GetRole(Guid roleId)
        {
            return Uow.Roles.GetById(roleId);
        }

        /// <summary>
        /// </summary>
        /// <returns></returns>
        public ICollection<Role> GetRoles()
        {
            List<Role> rez = Uow.Roles.GetAll(false)
                                .ToList();
            Uow.Permissions.GetPermissionsForAllRoles();
            return rez;
        }

        public ICollection<Role> GetRolesByUserType(UserTypeDictionary userType)
        {
            List<Role> rez = Uow.Roles.GetRolesByUserType(userType)
                                .ToList();
            Uow.Permissions.GetPermissionsForAllRoles();
            return rez;
        }

        public ICollection<Role> GetRolesByUserId(Guid userId)
        {
            return Uow.Roles.GetRolesByUserId(userId);
        }

        /// <summary>
        /// </summary>
        /// <param name="role"></param>
        public void SaveRole(Role role)
        {
            if (role.Id == Guid.Empty)
                role.Id = Guid.NewGuid();

            if (!Uow.Roles.IsExist(role.Id))
                Uow.Roles.Add(role);
            else
                Uow.Roles.Update(role);

            Uow.Commit();
        }

        public void DeleteUserToRoles(IEnumerable<UserToRole> freeUserToRoles)
        {
            foreach (UserToRole userRole in freeUserToRoles)
            {
                Uow.UserToRoles.Delete(userRole.Id);
            }

            Uow.Commit();
        }

        #endregion Roles

        #region UserGroups

        /// <summary>
        /// </summary>
        /// <param name="userGroupId"></param>
        /// <returns></returns>
        public UserGroup GetUserGroup(Guid userGroupId)
        {
            return Uow.UserGroups.GetById(userGroupId);
        }

        /// <summary>
        /// </summary>
        /// <returns></returns>
        public IEnumerable<UserGroup> GetUsersGroups()
        {
            return Uow.UserGroups.GetAll()
                      .ToList();
        }

        /// <summary>
        /// </summary>
        /// <param name="userGroup"></param>
        public void SaveUserGroup(UserGroup userGroup)
        {
            if (userGroup.Id == Guid.Empty)
                userGroup.Id = Guid.NewGuid();

            if (!Uow.UserGroups.IsExist(userGroup.Id))
                Uow.UserGroups.Add(userGroup);
            else
                Uow.UserGroups.Update(userGroup);

            Uow.Commit();
        }

        public void DeleteUserToUserGroups(List<UserToUserGroup> freeUserToUserGroups)
        {
            foreach (UserToUserGroup userGroup in freeUserToUserGroups)
            {
                Uow.UserToUserGroups.Delete(userGroup);
            }

            Uow.Commit();
        }

        #endregion UserGroups

        #region Certificates

        public void SaveCertificateRequest(CertificateRequest certificateRequest)
        {
            if (certificateRequest.Id == Guid.Empty)
                certificateRequest.Id = Guid.NewGuid();

            if (!Uow.CertificateRequests.IsExist(certificateRequest.Id))
                Uow.CertificateRequests.Add(certificateRequest);
            else
                Uow.CertificateRequests.Update(certificateRequest);

            Uow.Commit();
        }

        public void AddCertificate(string certificateData,
                                   Guid userId)
        {
            User user = GetUser(userId);

            if (user == null)
                throw new Exception("Не найден пользователь id: " + userId);

            X509Certificate2 cert = loadCertFromRequestData(certificateData);

            if (cert == null)
                throw new Exception("Неверный формат сертификата");

            if (Uow.Certificates.Exists(cert.Thumbprint))
            {
                IEnumerable<Certificate> oldSertificates = Uow.Certificates.GetByThumbprint(cert.Thumbprint);
                if (oldSertificates != null && oldSertificates.Any(c => c.IsActive))
                    throw new Exception("Сертификат уже существует и используется другим пользователем");
            }

            var certificate = new Certificate
                              {
                                      Id = Guid.NewGuid(),
                                      User = user,
                                      UserId = user.Id,
                                      CertificateInBase64String = Convert.ToBase64String(cert.RawData),
                                      IssuerName = Convert.ToBase64String(cert.IssuerName.RawData),
                                      SubjectName = Convert.ToBase64String(cert.SubjectName.RawData),
                                      ValidityPeriodStart = cert.NotBefore,
                                      ValidityPeriodEnd = cert.NotAfter,
                                      SerialNumber = cert.GetSerialNumberString(),
                                      SignatureAlgorithmId = cert.SignatureAlgorithm.Value,
                                      VersionNumber = cert.Version.ToString(),
                                      Thumbprint = cert.Thumbprint
                              };

            Uow.Certificates.Add(certificate);
            Uow.Commit();
        }

        public Guid SaveCertificate(Certificate certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException("certificate");

            if (certificate.Id == Guid.Empty)
                certificate.Id = Guid.NewGuid();

            if (!Uow.Certificates.Exists(certificate.Thumbprint))
                Uow.Certificates.Add(certificate);
            else
                Uow.Certificates.Update(certificate);

            if (certificate.Id == Guid.Empty)
            {
                certificate.Id = Guid.NewGuid();
                Uow.Certificates.Add(certificate);
            }
            else
            {
                Uow.Certificates.Update(certificate);
            }

            Uow.Commit();
            return certificate.Id;
        }

        /// <summary>
        /// </summary>
        /// <param name="certificateId"></param>
        /// <returns></returns>
        public Certificate GetCertificate(Guid certificateId)
        {
            return Uow.Certificates.GetById(certificateId);
        }

        public Certificate GetCertificate(string thumbprint)
        {
            return Uow.Certificates.GetByThumbprint(thumbprint).FirstOrDefault();
        }

        /// <summary>
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public ICollection<Certificate> GetCertificates(Guid userId)
        {
            return Uow.Certificates.GetUserCertificates(userId);
        }

        public IEnumerable<Certificate> GetOldCertificates(TimeSpan time)
        {
            IEnumerable<Certificate> rez = Uow.Certificates.GetOldCertificates(time);
            IEnumerable<Guid> users = rez.Select(c => c.UserId);
            Uow.Users.GetUsersById(users);
            return rez;
        }

        /// <summary>
        /// </summary>
        /// <param name="certificateRequestId"></param>
        /// <returns></returns>
        public CertificateRequest GetCertificateRequest(Guid certificateRequestId)
        {
            return Uow.CertificateRequests.GetById(certificateRequestId);
        }

        /// <summary>
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public ICollection<CertificateRequest> GetCertificateRequests(Guid userId)
        {
            return Uow.CertificateRequests.GetUserCertificateRequests(userId);
        }

        private static X509Certificate2 loadCertFromRequestData(string certData)
        {
            X509Certificate2 cert;

            try
            {
                try
                {
                    cert = new X509Certificate2(certData);
                }
                catch (CryptographicException)
                {
                    cert = new X509Certificate2(Convert.FromBase64String(certData));
                }
                catch (PathTooLongException)
                {
                    cert = new X509Certificate2(Convert.FromBase64String(certData));
                }
                catch (ArgumentException)
                {
                    cert = new X509Certificate2(Convert.FromBase64String(certData));
                }
            }
            catch (ArgumentNullException)
            {
                return null;
            }
            catch (FormatException)
            {
                return null;
            }
            catch (CryptographicException)
            {
                return null;
            }

            return cert;
        }

        #endregion Certificates

        #region Nested type: AuditPalainRow

        private class AuditPlainRow
        {
            public DateTime Time { get; set; }
            public string User { get; set; }
            public string Host { get; set; }
            public string Source { get; set; }
            public string Destination { get; set; }
            public string EventID { get; set; }
            public string EntryType { get; set; }
            public string DocumentInfo { get; set; }
            public string Message { get; set; }

            public override string ToString()
            {
                return string.Format("@@@ Time=\"{0}\",Host=\"{1}\",User=\"{2}\",Source=\"{3}\",Destination=\"{4}\",EventID={5},EntryType=\"{6}\",DocumentInfo=\"{7}\",Message=\"{8}\"",
                                     Time.ToString("G"),
                                     Host,
                                     User,
                                     Source,
                                     Destination,
                                     EventID,
                                     EntryType,
                                     DocumentInfo,
                                     Message);
            }
        }

        #endregion

        public IEnumerable<Session> GetSessions()
        {
            return Uow.Sessions.GetSessions(true);
        }

        public List<User> GetUsersByPermission(PermissionIdDictionary permissionId)
        {
            return Uow.Users.GetUsersByPermission(permissionId);
        }

        #region Audit
        internal struct AuditIndexKey
        {
            private AuditOperationDictionary _operation;
            private AuditObjectDictionary? _object;

            internal AuditIndexKey(AuditOperationDictionary operation, AuditObjectDictionary? o) : this()
            {
                _operation = operation;
                _object = o;
            }

            internal AuditIndexKey(AuditObjectDictionary? o, AuditOperationDictionary operation) : this()
            {
                _operation = operation;
                _object = o;
            }
        }

        internal struct AuditIndexVal
        {
            internal readonly bool LogAble;

            internal AuditIndexVal(bool logAble) : this()
            {
                LogAble = logAble;
            }
        }

        private static readonly Dictionary<AuditIndexKey, AuditIndexVal> AuditIndex = new Dictionary
            <AuditIndexKey, AuditIndexVal>
        {
            {new AuditIndexKey(AuditOperationDictionary.Initialization,                           null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetAuthority,                     null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_AdeemUserToClientAuthority,       null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_FindClients,                      null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_AddUserToClientAuthority,         null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_FindIssuers,                      null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetIssuerSecurityTypes,           null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_FindSecurities,                   null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientNames,                   null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientQuestionnaireInfo,       null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientContract,                null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientCashAccountsRests,       null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientSecuritiesAccountsRests, null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientSecuritiesAccounts,      null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_FindClientBankingDetails,         null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientPortfolioStructure,      null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetForwardMarketDeals,            null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetStockMarketDeals,              null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientPositionsMove,           null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientCashMove,                null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientSecuritiesMove,          null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetClientProxies,                 null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetCashSections,                  null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetIdentityDocumentTypes,         null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetSecuritiesSections,            null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetTradingFloors,                 null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetDealTypes,                     null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetBankStorageAccounts,           null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetSecuritiesStorage,             null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetSecuritiesStorages,            null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetExchangeDocumentsForSign,      null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetExchangeDocuments,             null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_DeleteExchangeDocument,           null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_GetExchangeDocument,              null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.StageDB_CheckAuthority,                   null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Auth,                                     null), new AuditIndexVal(true)},

            //Services
            {new AuditIndexKey(AuditOperationDictionary.Services_ActivateTasks,          null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_Delay,                  null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_CheckDocsForImport,     null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_ComposeNotifications,   null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_DropOldSessions,        null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_NotifyAuthorityDead,    null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_NotifyCertificateDead,  null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_NotifyExpiredTasks,     null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_SendEmailNotifications, null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_SendWebNotifications,   null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_SheduleCreateProcess,   null), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditOperationDictionary.Services_ReadEmailSettings,      null), new AuditIndexVal(true)},
            
            {new AuditIndexKey(AuditObjectDictionary.Document,                     AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Document,                     AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Document,                     AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Document,                     AuditOperationDictionary.Print),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.IncomeDocumentNumber,         AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.OutcomeDocumentNumber,        AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.SystemLog,                    AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.SystemLog,                    AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Password,                     AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Certificate,                  AuditOperationDictionary.Read),     new AuditIndexVal(false)},
            {new AuditIndexKey(AuditObjectDictionary.Certificate,                  AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Certificate,                  AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Role,                         AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Role,                         AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Role,                         AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.UserGroup,                    AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.UserGroup,                    AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.UserGroup,                    AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentProcessTask,          AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentProcessTask,          AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentProcessTask,          AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentProcessTemplateStage, AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentProcessTemplateStage, AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentProcessTemplate,      AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentProcessTemplate,      AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentProcessTemplate,      AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Shedule,                      AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Shedule,                      AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.UserSetting,                  AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.UserSetting,                  AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentType,                 AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Visa,                         AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.EventSubscribes,              AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.EventSubscribes,              AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.EventSubscribes,              AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.NotificationTemplate,         AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.NotificationTemplate,         AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.NotificationTemplate,         AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.NotificationType,             AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.NotificationMessageTemplate,  AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentPrintTemplate,        AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.DocumentPrintTemplate,        AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.User,                         AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.User,                         AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.User,                         AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.CertificateRequest,           AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.CertificateRequest,           AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Permission,                   AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.EmailSmtpSettings,            AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.EmailSmtpSettings,            AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.CaSettings,                   AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.CaSettings,                   AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.StageDBSettings,              AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.StageDBSettings,              AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.AuthorizationPolicySettings,  AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.CyclesSettings,               AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Calendar,                     AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Calendar,                     AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.ClientsGroup,                 AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.ClientsGroup,                 AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.ClientsGroup,                 AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.ClientsGroup,                 AuditOperationDictionary.Delete),   new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.CommonSetting,                AuditOperationDictionary.Read),     new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.CommonSetting,                AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Session,                      AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Session,                      AuditOperationDictionary.Delete),   new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Session,                      AuditOperationDictionary.ReadMany), new AuditIndexVal(true)},
            {new AuditIndexKey(AuditObjectDictionary.Notification,                 AuditOperationDictionary.Write),    new AuditIndexVal(true)},
            
        };

        private void AuditActionInner(AuditOperationDictionary actionType,
                                      AuditObjectDictionary? auditObjectDictionary,
                                      ClientName clientName,
                                      Guid auditThreadId,
                                      Session session,
                                      bool accessGranted = true,
                                      string comment = "",
                                      IEnumerable<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null,
                                      Guid? documentMetadataId = null)
        {
            var auditIndexKey = new AuditIndexKey(actionType, auditObjectDictionary);
            if (AuditIndex.ContainsKey(auditIndexKey))
            {
                var time = DateTime.Now;

                AuditOperation(time,
                               actionType,
                               auditObjectDictionary,
                               auditThreadId,
                               session,
                               clientName != null ? clientName.Id : (int?) null,
                               accessGranted, 
                               comment,
                               auditInfo,
                               documentMetadataId);

                if (AuditIndex[auditIndexKey].LogAble)
                {
                    LogAudit(time, session, clientName, actionType,auditObjectDictionary, accessGranted, comment, auditInfo);
                }
            }
            else
            {
                throw new ApplicationException(string.Format("Аудит действия {0} над объектом {1} не поддерживается", actionType, auditObjectDictionary));
            }
        }

        private int AuditOperation(
            DateTime time, 
            AuditOperationDictionary actionType, 
            AuditObjectDictionary? auditObject,
            Guid auditThreadId, 
            Session session, 
            int? client,
            bool accessGranted = true, 
            string comment = "",
            IEnumerable<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null,
            Guid? documentMetadataId = null)
        {
            int auditRowNumber = Uow.GetNextCounterValue(CounterTypeDictionary.AuditRowNumberCounter);

            var auditOperation = new AuditRow
            {
                Id = Guid.NewGuid(),
                RowNumber = auditRowNumber,
                CorrelationId = auditThreadId,
                ActionType = actionType,
                AuditObject = auditObject,
                UserId = session.User.Id,
                DocumentMetadataId = documentMetadataId,
                SessionId = session.Id,
                Client = client,
                OperationDateTime = time,
                AccessGranted = accessGranted,
                OperationInfo = comment,
                AuditInfoRows = auditInfo == null
                    ? null
                    : auditInfo.Select(i => new AuditInfoRow
                    {
                        Id = Guid.NewGuid(),
                        InfoKeyId = i.Key,
                        InfoKey = i.Key.ToString(),
                        Info = i.Value
                    }).ToList()
            };

            Uow.Audit.Add(auditOperation);
            Uow.Commit();

            return auditRowNumber;
        }


        private void LogAudit(
            DateTime operationDateTime, 
            Session session, 
            ClientName clientInfo,
            AuditOperationDictionary actionType, 
            AuditObjectDictionary? auditObject, 
            bool accessGranted = true,
            string comment = "", IEnumerable<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null)
        {
            string logInfo = string.Format(
                "@@@ Time=\"{0}\",IP=\"{1}\",SessionId=\"{2}\"{3}{4},AuditOperationType=\"{6}\",AuditOperationTypeName=\"{5}\"{7},AccessGranted=\"{8}\"{9}",
                operationDateTime.ToString("G"),
                session.ClientIpAddress,
                session.Id,
                session.User != null ? string.Format(",Login=\"{0}\",User=\"{1}\"", session.User.Login, session.User.GetFullName()) : "",
                clientInfo != null ? string.Format(",Client=\"{0}({1})\"", clientInfo.FullName, clientInfo.Id) : "",
                getAuditOperationName(actionType),
                actionType.ToString(),
                auditObject != null
                    ? string.Format(",AuditObjectType=\"{0}\",AuditObjectTypeName=\"{1}\"", auditObject.Value.ToString(),getAuditObjectName(auditObject.Value))
                    : "",
                accessGranted,
                string.IsNullOrWhiteSpace(comment)?"":string.Format(",Comment=\"{0}\"",comment));

            if (auditInfo != null)
                logInfo = auditInfo.Aggregate(logInfo, (current, aInfo) =>
                        string.Format("{0},AuditInfoType =\"{1}\",AuditInfoTypeName=\"{2}\",AuditInfoTypeValue=\"{3}\"", current, aInfo.Key, getAuditInfoKeyName(aInfo.Key), aInfo.Value));

            log.Info(logInfo);
        }

        #region AuditActions
        public void AuditAction(AuditOperationActionTypeDictionary actionType,
                                ClientName clientName,
                                Guid auditThreadId,
                                Session session,
                                bool accGranted = true,
                                string comment = "")
        {
            AuditActionInner((AuditOperationDictionary) actionType,
                             null,
                             clientName,
                             auditThreadId,
                             session,
                             accGranted,
                             comment);
        }

        public void AuditAction_Document(AuditOperationObjectActionDictionary actionType,
                                          ClientName clientName,
                                          DocumentMetadata document,
                                          Guid auditThreadId,
                                          Session session,
                                          bool accessGranted = true,
                                          string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Document;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (document != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocId,
                                                                                     document.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocNumber,
                                                                                     document.BankDocumentNumber),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocDate,
                                                                                     document.Created.ToString("G")),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocType,
                                                                                     Uow.DocumentTypes.GetByTypeId(document.DocumentTypeId).Name),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo,
                             document != null
                                     ? document.Id
                                     : (Guid?) null);
        }

        public void AuditAction_ExchangeDocument(AuditOperationObjectActionDictionary actionType,
                                          ClientName clientName,
                                          ExchangeDocument document,
                                          Guid auditThreadId,
                                          Session session,
                                          bool accessGranted = true,
                                          string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Document;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (document != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocId,
                                                                                     document.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocNumber,
                                                                                     document.DocumentNumber),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocDate,
                                                                                     document.DocumentDate.ToString("G")),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocType,
                                                                                     document.DocumentTypeId.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_PrintDocument(ClientName clientName,
                                               DocumentMetadata document,
                                               Guid auditThreadId,
                                               Session session,
                                               bool accessGranted = true,
                                               string comment = "")
        {
            const AuditOperationDictionary actionType = AuditOperationDictionary.Print;
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Document;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (document != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocId,
                                                                                     document.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocNumber,
                                                                                     document.BankDocumentNumber),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocDate,
                                                                                     document.Created.ToString("G")),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocType,
                                                                                     document.DocumentTypeId.ToString()),
                            };

            AuditActionInner(actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_IncomeDocumentNumber(AuditOperationObjectActionDictionary actionType,
                                                      ClientName clientName,
                                                      string documentNumber,
                                                      Guid auditThreadId,
                                                      Session session,
                                                      bool accessGranted = true,
                                                      string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.IncomeDocumentNumber;
            var auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocNumber,
                                                                                     documentNumber),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_OutcomeDocumentNumber(AuditOperationObjectActionDictionary actionType,
                                                       ClientName clientName,
                                                       string documentNumber,
                                                       Guid auditThreadId,
                                                       Session session,
                                                       bool accessGranted = true,
                                                       string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.OutcomeDocumentNumber;
            var auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocNumber,
                                                                                     documentNumber),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_SystemLog(AuditOperationObjectActionDictionary actionType,
                                           LogRow logRow,
                                           Guid auditThreadId,
                                           Session session,
                                           bool accessGranted = true,
                                           string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.SystemLog;
            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (logRow != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.logRowId,
                                                                                     logRow.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.logRowSubject,
                                                                                     logRow.Subject),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.logRowCreated,
                                                                                     logRow.Created.ToString("G")),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_Password(AuditOperationObjectActionDictionary actionType,
                                          User user,
                                          Guid auditThreadId,
                                          Session session,
                                          bool accessGranted = true,
                                          string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Password;
            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (user != null)
            {
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userId,
                                                                                     user.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userName,
                                                                                     user.GetFullName()),
                            };
            }

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_Certificate(AuditOperationObjectActionDictionary actionType,
                                             Certificate certificate,
                                             Guid auditThreadId,
                                             Session session,
                                             bool accessGranted = true,
                                             string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Certificate;
            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (certificate != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.certificateId,
                                                                                     certificate.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.certificateIssuerName,
                                                                                     certificate.IssuerName),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.certificateSerialNumber,
                                                                                     certificate.SerialNumber),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.certificateSubjectName,
                                                                                     certificate.SubjectName),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.certificateActive,
                                                                                     certificate.IsActive.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_Role(AuditOperationObjectActionDictionary actionType,
                                      Role role,
                                      Guid auditThreadId,
                                      Session session,
                                      bool accessGranted = true,
                                      string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Role;
            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (role != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocId,
                                                                                     role.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocNumber,
                                                                                     role.Title),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocDate,
                                                                                     role.UserType.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_UserGroup(AuditOperationObjectActionDictionary actionType,
                                          UserGroup userGroup,
                                          Guid auditThreadId,
                                          Session session,
                                          bool accessGranted = true,
                                          string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.UserGroup;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (userGroup != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userGroupId,
                                                                                     userGroup.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userGroupName,
                                                                                     userGroup.Name),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_DocumentProcessesTask(AuditOperationObjectActionDictionary actionType,
                                                       ClientName clientName,
                                                       DocumentProcessTask documentProcessTask,
                                                       Guid auditThreadId,
                                                       Session session,
                                                       bool accessGranted = true,
                                                       string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.DocumentProcessTask;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (documentProcessTask != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.TaskId,
                                                                                     documentProcessTask.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.TaskName,
                                                                                     documentProcessTask.Name),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_DocumentProcessTemplateStage(AuditOperationObjectActionDictionary actionType,
                                                             DocumentProcessTemplateStage documentProcessTemplateStage,
                                                             Guid auditThreadId,
                                                             Session session,
                                                             bool accessGranted = true,
                                                             string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.DocumentProcessTemplateStage;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (documentProcessTemplateStage != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.StageId,
                                                                                     documentProcessTemplateStage.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.StageName,
                                                                                     documentProcessTemplateStage.Name),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_DocumentProcessTemplate(AuditOperationObjectActionDictionary actionType,
                                                         DocumentProcessTemplate documentProcessTemplate,
                                                         Guid auditThreadId,
                                                         Session session,
                                                         bool accessGranted = true,
                                                         string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.DocumentProcessTemplate;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (documentProcessTemplate != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.ProcessTemplateId,
                                                                                     documentProcessTemplate.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.ProcessTemplateName,
                                                                                     documentProcessTemplate.Name),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_Shedule(AuditOperationObjectActionDictionary actionType,
                                         Shedule shedule,
                                         Guid auditThreadId,
                                         Session session,
                                         bool accessGranted = true,
                                         string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Shedule;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (shedule != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.sheduleId,
                                                                                     shedule.Id.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_UserSetting(AuditOperationObjectActionDictionary actionType,
                                             ClientName clientName,
                                             UserSettingsDictionary settingType,
                                             string setting,
                                             Guid auditThreadId,
                                             Session session,
                                             bool accessGranted = true,
                                             string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.UserSetting;

            var auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.UserSetting,
                                                                                     settingType.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.UserSettingValue,
                                                                                     setting),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_DocumentType(AuditOperationObjectActionDictionary actionType,
                                              ClientName clientName,
                                              DocumentTypeDictionary? documentType,
                                                       Guid auditThreadId,
                                                       Session session,
                                              bool accessGranted = true,
                                              string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.DocumentType;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (documentType != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.documentType,
                                                                                     documentType.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_Visa(AuditOperationObjectActionDictionary actionType,
                                      ClientName clientName,
                                      DocumentMetadata document,
                                      Certificate certificate,
                                      Guid auditThreadId,
                                      Session session,
                                      bool accessGranted = true,
                                      string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Visa;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (document != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocId,
                                                                                     document.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocNumber,
                                                                                     document.BankDocumentNumber),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocDate,
                                                                                     document.Created.ToString("G")),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocType,
                                                                                     document.DocumentTypeId.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.certificateId,
                                                                                     certificate.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.certificateIssuerName,
                                                                                     certificate.IssuerName),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.certificateSerialNumber,
                                                                                     certificate.SerialNumber),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.certificateSubjectName,
                                                                                     certificate.SubjectName),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_EventSubscribe(AuditOperationObjectActionDictionary actionType,
                                               ClientName clientName,
                                               DocumentProcessEventSubscribe eventSubscribe,
                                               Guid auditThreadId,
                                               Session session,
                                               bool accessGranted = true,
                                               string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.EventSubscribes;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (eventSubscribe != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.eventSubscribeId,
                                                                                     eventSubscribe.Id.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_NotificationTemplate(AuditOperationObjectActionDictionary actionType,
                                                     NotificationTemplate notificationTemplate,
                                                     Guid auditThreadId,
                                                     Session session,
                                                     bool accessGranted = true,
                                                     string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.NotificationTemplate;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (notificationTemplate != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.notificationTemplateId,
                                                                                     notificationTemplate.Id.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_NotificationType(AuditOperationObjectActionDictionary actionType,
                                                  ClientName clientName,
                                                  NotificationType notificationType,
                                                  Guid auditThreadId,
                                                  Session session,
                                                  bool accessGranted = true,
                                                  string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.NotificationType;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (notificationType != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.NotificationType,
                                                                                     notificationType.Type.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.NotificationTypeName,
                                                                                     notificationType.Name),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_NotificationMessageTemplate(AuditOperationObjectActionDictionary actionType,
                                                            ClientName clientName,
                                                            NotificationMessageTemplate notificationMessageTemplate,
                                                            Guid auditThreadId,
                                                            Session session,
                                                            bool accessGranted = true,
                                                            string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.NotificationMessageTemplate;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (notificationMessageTemplate != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.NotificationMessageTemplateType,
                                                                                     notificationMessageTemplate.Type.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.NotificationMessageTemplateId,
                                                                                     notificationMessageTemplate.Id.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_DocumentPrintTemplate(AuditOperationObjectActionDictionary actionType,
                                                       ClientName clientName,
                                                       DocumentPrintTemplate documentPrintTemplate,
                                                       Guid auditThreadId,
                                                       Session session,
                                                       bool accessGranted = true,
                                                       string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.DocumentPrintTemplate;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (documentPrintTemplate != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.documentPrintTemplateType,
                                                                                     documentPrintTemplate.Type.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.documentPrintTemplateId,
                                                                                     documentPrintTemplate.Id.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             clientName,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_User(AuditOperationObjectActionDictionary actionType,
                                      User user,
                                                       Guid auditThreadId,
                                                       Session session,
                                      bool accessGranted = true,
                                      string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.User;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (user != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userName,
                                                                                     user.GetFullName()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userId,
                                                                                     user.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userCreated,
                                                                                     user.Created.ToString("G")),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userEmail,
                                                                                     user.Email),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userLogin,
                                                                                     user.Login),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_CertificateRequest(AuditOperationObjectActionDictionary actionType,
                                                   CertificateRequest certificateRequest,
                                                   Guid auditThreadId,
                                                   Session session,
                                                   bool accessGranted = true,
                                                   string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.CertificateRequest;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (certificateRequest != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.CertificateRequestId,
                                                                                     certificateRequest.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.CertificateRequestCreated,
                                                                                     certificateRequest.CreationTime.ToString("G")),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.CertificateRequestSubjectUserId,
                                                                                     certificateRequest.SubjectUser.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.CertificateRequestSubjectUserName,
                                                                                     certificateRequest.SubjectUser.GetFullName()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_Permission(AuditOperationObjectActionDictionary actionType,
                                           Permission permission,
                                           Guid auditThreadId,
                                           Session session,
                                           bool accessGranted = true,
                                           string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Permission;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (permission != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.CertificateRequestId,
                                                                                     permission.Id.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_EmailSettings(AuditOperationObjectActionDictionary actionType,
                                              EmailSettings settings,
                                              Guid auditThreadId,
                                              Session session,
                                              bool accessGranted = true,
                                              string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.EmailSmtpSettings;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (settings != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.CommonSenderEmail,
                                                                                     settings.CommonSenderEmail),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.EmailSmtpServerHostOrIp,
                                                                                     settings.SmtpHostOrIp),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.EmailSmtpUserDomain,
                                                                                     settings.SmtpSenderDomain),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.EmailSmtpUserId,
                                                                                     settings.SmtpSenderLogin),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.EmailSmtpUserPassword,
                                                                                     settings.SmtpSenderPassword),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.IsEmailSendEnabled,
                                                                                     settings.IsEmailSendEnabled.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.EmailSmtpSendEventDelay,
                                                                                     settings.SmtpEmailSendEventDelay.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.EmailSmtpServerPort,
                                                                                     settings.SmtpPort.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_CaSettings(AuditOperationObjectActionDictionary actionType,
                                           CaSettings settings,
                                           Guid auditThreadId,
                                           Session session,
                                           bool accessGranted = true,
                                           string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.CaSettings;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (settings != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.CaSiteUrl,
                                                                                     settings.CaSiteUrl),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_StageDbSettings(AuditOperationObjectActionDictionary actionType,
                                                StageDbSettings settings,
                                                Guid auditThreadId,
                                                Session session,
                                                bool accessGranted = true,
                                                string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.StageDBSettings;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (settings != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.StageDBWebServiceBaseUrl,
                                                                                     settings.WebServiceBaseUrl),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_AuthorizationPolicySettings(AuditOperationObjectActionDictionary actionType,
                                                            AuthorizationPolicySettings settings,
                                                            Guid auditThreadId,
                                                            Session session,
                                                            bool accessGranted = true,
                                                            string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.AuthorizationPolicySettings;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (settings != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.AllowReadOnlyIfInvalidKey,
                                                                                     settings.AllowReadOnlyIfInvalidKey.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.CheckRevocationSatusMode,
                                                                                     settings.CheckRevocationSatusMode.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_CyclesSettings(AuditOperationObjectActionDictionary actionType,
                                                CyclesSettings settings,
                                                Guid auditThreadId,
                                                Session session,
                                                bool accessGranted = true,
                                                string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.CyclesSettings;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (settings != null)
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.ComposeNotificationsDelay,
                                                                                     settings.ComposeNotificationsDelay.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocumentBeforeDeadlineNotificationTimeSpan,
                                                                                     settings.DocumentBeforeDeadlineNotificationTimeSpan.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocumentNextDeadlineSpamTimeSpan,
                                                                                     settings.DocumentNextDeadlineSpamTimeSpan.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocumentSendTaskNotificationDelay,
                                                                                     settings.DocumentSendTaskNotificationDelay.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.DocumentSheduleCreateProcessDelay,
                                                                                     settings.DocumentSheduleCreateProcessDelay.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.NotificationsHeap,
                                                                                     settings.NotificationsHeap.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.NotifyBeforeTooOldAuthorityTime,
                                                                                     settings.NotifyBeforeTooOldAuthorityTime.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.NotifyBeforeTooOldCertificateTime,
                                                                                     settings.NotifyBeforeTooOldCertificateTime.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.NotifyDeadAuthoritiesDelay,
                                                                                     settings.NotifyDeadAuthoritiesDelay.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.NotifyDeadCertificatesDelay,
                                                                                     settings.NotifyDeadCertificatesDelay.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.SendWebMessageNotificationsDelay,
                                                                                     settings.SendWebMessageNotificationsDelay.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.SessionInactiveForNotificationTime,
                                                                                     settings.SessionInactiveForNotificationTime.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.SessionsDropDelay,
                                                                                     settings.SessionsDropDelay.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.VisaBySecondResponceDelay,
                                                                                     settings.VisaBySecondResponceDelay.ToString()),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_Calendar(AuditOperationObjectActionDictionary actionType,
                                          WorkingCalendar calendar,
                                          Guid auditThreadId,
                                          Session session,
                                          bool accessGranted = true,
                                          string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Calendar;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (calendar != null)
            {
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.calendarId,
                                                                                     calendar.Id.ToString()),
                            };
                if (calendar.WorkingUser != null)
                {
                    auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userId,
                                                                                   calendar.WorkingUser.Id.ToString()));
                    auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userName,
                                                                                   calendar.WorkingUser.GetFullName()));
                }
            }
            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_ClientsGroup(AuditOperationObjectActionDictionary actionType,
                                              ClientsGroup clientsGroup,
                                              Guid auditThreadId,
                                              Session session,
                                              bool accessGranted = true,
                                              string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.ClientsGroup;

            List<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (clientsGroup != null)
            {
                auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.clientsGroupId,
                                                                                     clientsGroup.Id.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.clientsGroupName,
                                                                                     clientsGroup.Name),
                            };

                if (clientsGroup.OwnerUser != null)
                {
                    auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userId,
                                                                                   clientsGroup.OwnerUser.Id.ToString()));
                    auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userName,
                                                                                   clientsGroup.OwnerUser.GetFullName()));
                }
            }

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_SessionMaxTimeout(AuditOperationObjectActionDictionary actionType,
                                                   UserTypeDictionary userType,
                                                   TimeSpan sessionMaxTimeout,
                                                   Guid auditThreadId,
                                                   Session session,
                                                   bool accessGranted = true,
                                                   string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.CommonSetting;

            var auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>();

            if (userType == UserTypeDictionary.BankClient)
                auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.SessionInactiveClientUserForDropTime,
                                                                               sessionMaxTimeout.ToString()));
            auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.SessionInactiveBankUserForDropTime,
                                                                           sessionMaxTimeout.ToString()));

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_CommonSetting(AuditOperationObjectActionDictionary actionType,
                                              CommonSettingsDictionary settingType,
                                              string setting,
                                              Guid auditThreadId,
                                              Session session,
                                              bool accessGranted = true,
                                              string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.CommonSetting;

            var auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>
                            {
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.CommonSetting,
                                                                                     settingType.ToString()),
                                    new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.CommonSettingValue,
                                                                                     setting),
                            };

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_Session(SessionActionDictionary SessionActionType,
                                        Guid auditThreadId,
                                        Session session,
                                        bool accessGranted = true,
                                        string comment = "")
        {
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.Session;
            AuditOperationDictionary actionType = 0;

            switch (SessionActionType)
            {
                case SessionActionDictionary.Open:
                    actionType = AuditOperationDictionary.Write;
                    break;
                case SessionActionDictionary.Close:
                    actionType = AuditOperationDictionary.Delete;
                    break;
                case SessionActionDictionary.ReadMany:
                    actionType = AuditOperationDictionary.ReadMany;
                    break;
            }

            var auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>();
            if (session != null)
            {
                auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.sessionId,
                                                                               session.Id.ToString()));
                auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.sessionOpened,
                                                                               session.Opened.ToString("G")));
                auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userId,
                                                                               session.User.Id.ToString()));
                auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.userName,
                                                                               session.User.GetFullName()));
            }

            AuditActionInner((AuditOperationDictionary) actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_CheckStageDBAuthority(IList<ClientName> clientNames,
                                                       Guid auditThreadId,
                                                       Session session)
        {
            const AuditOperationDictionary actionType = AuditOperationDictionary.StageDB_CheckAuthority;
            IEnumerable<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null;
            if (clientNames != null)
                auditInfo = clientNames.Select(c =>
                                               new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.Client,
                                                                                                string.Format(",Client=\"{0}({1})\"",
                                                                                                              c.FullName,
                                                                                                              c.Id)));

            AuditActionInner(actionType,
                             null,
                             null,
                             auditThreadId,
                             session,
                             clientNames == null || !clientNames.Any(),
                             "",
                             auditInfo);
        }

        public void AuditAction_DeleteClientsGroups(IEnumerable<Guid> clientsGroups,
                                                     Guid auditThreadId,
                                                     Session session,
                                                     bool accessGranted = true,
                                                     string comment = "")
        {
            const AuditOperationDictionary actionType = AuditOperationDictionary.Delete;
            const AuditObjectDictionary auditObjectDictionary = AuditObjectDictionary.ClientsGroup;

            var auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>();
            foreach (var clientsGroup in clientsGroups)
            {
                auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.clientsGroupId,
                                                                               clientsGroup.ToString()));
            }

            AuditActionInner(actionType,
                             auditObjectDictionary,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_Auth(AuthFailReasonDictionary? reason,
                                     Guid auditThreadId,
                                     Session session,
                                     bool accessGranted = false,
                                     string comment = "")
        {
            const AuditOperationDictionary actionType = AuditOperationDictionary.Auth;

            var auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>();

            if (reason != null)
                auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.AuthFailReason,
                                                                               reason.Value.ToString()));

            AuditActionInner(actionType,
                             null,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        public void AuditAction_Notification(Notification notification,
                                             Guid auditThreadId,
                                             Session session,
                                             bool accessGranted = false,
                                             string comment = "")
        {
            var auditInfo = new List<KeyValuePair<AuditInfoKeyDictionary, string>>();

            if (notification != null)
            {
                auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.notificationId,
                                                                               notification.Id.ToString()));
                auditInfo.Add(new KeyValuePair<AuditInfoKeyDictionary, string>(AuditInfoKeyDictionary.notificationStatus,
                                                                               notification.NotificationStatus.ToString()));
            }

            AuditActionInner(AuditOperationDictionary.Write,
                             AuditObjectDictionary.Notification,
                             null,
                             auditThreadId,
                             session,
                             accessGranted,
                             comment,
                             auditInfo);
        }

        #endregion AuditActions
        private string getAuditInfoKeyName(AuditInfoKeyDictionary auditInfoKey)
        {
            switch (auditInfoKey)
            {
                case AuditInfoKeyDictionary.Client:
                    return "Клиент";
                case AuditInfoKeyDictionary.AllowReadOnlyIfInvalidKey:
                    return "Разрешение входа только на чтение при неправильном ключе";
                case AuditInfoKeyDictionary.CaSiteUrl:
                    return "Адрес сервиса проверки сертификатов";
                case AuditInfoKeyDictionary.CertificateRequestCreated:
                    return "Дата создания запроса на создание сертификата";
                case AuditInfoKeyDictionary.CertificateRequestId:
                    return "Id запроса на создание сертификата";
                case AuditInfoKeyDictionary.CertificateRequestSubjectUserId:
                    return "Id пользователя, на которого создается сертификат";
                case AuditInfoKeyDictionary.CertificateRequestSubjectUserName:
                    return "Пользователь на которого создается сертификат";
                case AuditInfoKeyDictionary.CheckRevocationSatusMode:
                    return "Способ проверки статуса отзыва";
                case AuditInfoKeyDictionary.CommonSenderEmail:
                    return "Адрес отправителя";
                case AuditInfoKeyDictionary.CommonSetting:
                    return "Системная настройка";
                case AuditInfoKeyDictionary.CommonSettingValue:
                    return "Значение системной настройки";
                case AuditInfoKeyDictionary.ComposeNotificationsDelay:
                    return "Периодичность сборки уведомлений";
                case AuditInfoKeyDictionary.DocDate:
                    return "Дата создания документа";
                case AuditInfoKeyDictionary.DocId:
                    return "Id документа";
                case AuditInfoKeyDictionary.DocNumber:
                    return "Номер документа";
                case AuditInfoKeyDictionary.DocType:
                    return "Тип документа";
                case AuditInfoKeyDictionary.DocumentBeforeDeadlineNotificationTimeSpan:
                    return "Предупреждение об окончании обработки задачи";
                case AuditInfoKeyDictionary.DocumentNextDeadlineSpamTimeSpan:
                    return "Периодичность предупреждений";
                case AuditInfoKeyDictionary.DocumentSendTaskNotificationDelay:
                    return "Периодичность активации задач";
                case AuditInfoKeyDictionary.DocumentSheduleCreateProcessDelay:
                    return "Периодичность активации процессов обработки по расписанию";
                case AuditInfoKeyDictionary.EmailSmtpSendEventDelay:
                    return "Периодичность отправки email";
                case AuditInfoKeyDictionary.EmailSmtpServerHostOrIp:
                    return "Имя или IP адрес сервера";
                case AuditInfoKeyDictionary.EmailSmtpServerPort:
                    return "Порт Smtp сервера";
                case AuditInfoKeyDictionary.EmailSmtpUserDomain:
                    return "Домен пользователя";
                case AuditInfoKeyDictionary.EmailSmtpUserId:
                    return "Имя пользователя";
                case AuditInfoKeyDictionary.EmailSmtpUserPassword:
                    return "Пароль пользователя";
                case AuditInfoKeyDictionary.IsEmailSendEnabled:
                    return "Отправка email разрешена";
                case AuditInfoKeyDictionary.NotificationMessageTemplateId:
                    return "Id шаблона уведомления";
                case AuditInfoKeyDictionary.NotificationMessageTemplateType:
                    return "Тип шаблона уведомления";
                case AuditInfoKeyDictionary.NotificationType:
                    return "Id типа уведомления";
                case AuditInfoKeyDictionary.NotificationTypeName:
                    return "Тип уведомления";
                case AuditInfoKeyDictionary.NotificationsHeap:
                    return "Размер пачки уведомлений для обработки";
                case AuditInfoKeyDictionary.NotifyBeforeTooOldAuthorityTime:
                    return "Предупреждение об окончании доверенности";
                case AuditInfoKeyDictionary.NotifyBeforeTooOldCertificateTime:
                    return "Предупреждение об окончании сертификата";
                case AuditInfoKeyDictionary.NotifyDeadAuthoritiesDelay:
                    return "Периодичность предупреждений об окончании доверености";
                case AuditInfoKeyDictionary.NotifyDeadCertificatesDelay:
                    return "Периодичность предупреждений об окончании сертификата";
                case AuditInfoKeyDictionary.PagingPageSize:
                    return "Колличесто документов на странице";
                case AuditInfoKeyDictionary.ProcessTemplateId:
                    return "Id шаблона процесса обработки документов";
                case AuditInfoKeyDictionary.ProcessTemplateName:
                    return "Шаблон процесса обработки документов";
                case AuditInfoKeyDictionary.SendWebMessageNotificationsDelay:
                    return "Периодичность отправки Web уведомлений";
                case AuditInfoKeyDictionary.SessionInactiveBankUserForDropTime:
                    return "Длительность сессии сотрудника";
                case AuditInfoKeyDictionary.SessionInactiveClientUserForDropTime:
                    return "Длительность сессии клиента";
                case AuditInfoKeyDictionary.SessionInactiveForNotificationTime:
                    return "Предупреждение об окончании сессии";
                case AuditInfoKeyDictionary.SessionsDropDelay:
                    return "Переодичность проверки неактивных сессий";
                case AuditInfoKeyDictionary.StageDBWebServiceBaseUrl:
                    return "Адрес WCF-сервисов ";
                case AuditInfoKeyDictionary.StageId:
                    return "Id шаблона задачи";
                case AuditInfoKeyDictionary.StageName:
                    return "Шаблон задачи";
                case AuditInfoKeyDictionary.TaskId:
                    return "Id задачи";
                case AuditInfoKeyDictionary.TaskName:
                    return "Задача";
                case AuditInfoKeyDictionary.UserSetting:
                    return "Тип пользовательской настройки";
                case AuditInfoKeyDictionary.UserSettingValue:
                    return "Значение пользовательской настройки";
                case AuditInfoKeyDictionary.VisaBySecondResponceDelay:
                    return "Время на подпись ответного документа";
                case AuditInfoKeyDictionary.calendarId:
                    return "Id календаря";
                case AuditInfoKeyDictionary.certificateActive:
                    return "Активный сертификат";
                case AuditInfoKeyDictionary.certificateId:
                    return "Id сертификата";
                case AuditInfoKeyDictionary.certificateIssuerName:
                    return "Эмитент";
                case AuditInfoKeyDictionary.certificateSerialNumber:
                    return "Серийный номер сертификата";
                case AuditInfoKeyDictionary.certificateSubjectName:
                    return "Владелец";
                case AuditInfoKeyDictionary.clientsGroupId:
                    return "Id группы клиентов";
                case AuditInfoKeyDictionary.clientsGroupName:
                    return "Группа клиентов";
                case AuditInfoKeyDictionary.documentPrintTemplateId:
                    return "Id Шаблона печати документа";
                case AuditInfoKeyDictionary.documentPrintTemplateType:
                    return "Тип шаблона печати документа";
                case AuditInfoKeyDictionary.documentType:
                    return "Тип документа";
                case AuditInfoKeyDictionary.eventSubscribeId:
                    return "Id подписки на событие";
                case AuditInfoKeyDictionary.logRowCreated:
                    return "Дата записи в лог";
                case AuditInfoKeyDictionary.logRowId:
                    return "Id записи в лог";
                case AuditInfoKeyDictionary.logRowSubject:
                    return "Тема записи в лог";
                case AuditInfoKeyDictionary.notificationTemplateId:
                    return "Id Шаблона уведомления";
                case AuditInfoKeyDictionary.sheduleId:
                    return "Id действия по расписанию";
                case AuditInfoKeyDictionary.userCreated:
                    return "Дата создания пользователя";
                case AuditInfoKeyDictionary.userEmail:
                    return "Email пользователя";
                case AuditInfoKeyDictionary.userGroupId:
                    return "Id групы пользователей";
                case AuditInfoKeyDictionary.userGroupName:
                    return "Группа пользователей";
                case AuditInfoKeyDictionary.userId:
                    return "Id пользователя";
                case AuditInfoKeyDictionary.userLogin:
                    return "логин пользователя";
                case AuditInfoKeyDictionary.userName:
                    return "Имя пользователя";
                case AuditInfoKeyDictionary.AuthFailReason:
                    return "Причина отказа в авторизации";
                case AuditInfoKeyDictionary.sessionId:
                    return "Id сессии";
                case AuditInfoKeyDictionary.sessionOpened:
                    return "Начало сессии";
                case AuditInfoKeyDictionary.notificationId:
                    return "Id уведомления";
                case AuditInfoKeyDictionary.notificationStatus:
                    return "Статус уведомления";
                default:
                    throw new ArgumentOutOfRangeException("auditInfoKey",auditInfoKey.ToString());
            }
        }

        private string getAuditOperationName(AuditOperationDictionary auditOperationType)
        {
            switch (auditOperationType)
            {
                case AuditOperationDictionary.Initialization:
                    return "Инициализация пользовательского контекста";
                case AuditOperationDictionary.Read:
                    return "Чтение";
                case AuditOperationDictionary.Write:
                    return "Сохранение";
                case AuditOperationDictionary.ReadMany:
                    return "Чтение списка";
                case AuditOperationDictionary.Print:
                    return "Печать документа";
                case AuditOperationDictionary.SendEmail:
                    return "Отправка e-mail сообщения";
                case AuditOperationDictionary.Delete:
                    return "Удаление";
                case AuditOperationDictionary.StageDB_FindClients:
                    return "Промежуточная база. Поиск Клиентов";
                case AuditOperationDictionary.StageDB_ReadSettings:
                    return "Промежуточная база. Чтение настроей по доступу";
                case AuditOperationDictionary.StageDB_ChangeSettings:
                    return "Промежуточная база. Сохранение настроек по доступу";
                case AuditOperationDictionary.StageDB_AddUserToClientAuthority:
                    return "Промежуточная база. Добавление доверенности";
                case AuditOperationDictionary.StageDB_AdeemUserToClientAuthority:
                    return "Промежуточная база. Отзыв доверенности";
                case AuditOperationDictionary.StageDB_GetClientContract:
                    return "Промежуточная база. Чтение договора Клиента";
                case AuditOperationDictionary.StageDB_GetClientNames:
                    return "Промежуточная база. Чтение наименований Клиентов";
                case AuditOperationDictionary.StageDB_GetAuthority:
                    return "Промежуточная база. Чтение доверенности Клиента";
                case AuditOperationDictionary.StageDB_GetClientIds:
                    return "Промежуточная база. Чтение идентификаторов Клиентов";
                case AuditOperationDictionary.StageDB_FindIssuers:
                    return "Промежуточная база. Поиск эмитента";
                case AuditOperationDictionary.StageDB_GetIssuerSecurityTypes:
                    return "Промежуточная база. Чтение типов ЦБ эмитента";
                case AuditOperationDictionary.StageDB_FindSecurities:
                    return "Промежуточная база. Поиск выпуска ЦБ";
                case AuditOperationDictionary.StageDB_GetClientCashAccountsRests:
                    return "Промежуточная база. Чтение остатков на счетах денежных средств Клиента";
                case AuditOperationDictionary.StageDB_GetClientSecuritiesAccountsRests:
                    return "Промежуточная база. Чтение остатков на счетах ЦБ Клиента";
                case AuditOperationDictionary.StageDB_GetClientSecuritiesAccounts:
                    return "Промежуточная база. Чтение счетов ЦБ Клиента";
                case AuditOperationDictionary.StageDB_FindClientBankingDetails:
                    return "Промежуточная база. Поиск банковских реквизитов Клиента";
                case AuditOperationDictionary.StageDB_GetIdentityDocumentTypes:
                    return "Промежуточная база. Чтение типов документов, удостоверяющих личность";
                case AuditOperationDictionary.StageDB_GetCashSections:
                    return "Промежуточная база. Чтение разделов денежных средств";
                case AuditOperationDictionary.StageDB_GetSecuritiesSections:
                    return "Промежуточная база. Чтение разделов ЦБ";
                case AuditOperationDictionary.StageDB_GetClientPortfolioStructure:
                    return "Промежуточная база. Чтение структуры портфеля Клиента";
                case AuditOperationDictionary.StageDB_GetTradingFloors:
                    return "Промежуточная база. Чтение списка торговых площадок";
                case AuditOperationDictionary.StageDB_GetDealTypes:
                    return "Промежуточная база. Чтение типов сделок";
                case AuditOperationDictionary.StageDB_GetForwardMarketDeals:
                    return "Промежуточная база. Чтение сделок на срочном рынке";
                case AuditOperationDictionary.StageDB_GetStockMarketDeals:
                    return "Промежуточная база. Чтение сделок на фондовом рынке";
                case AuditOperationDictionary.StageDB_GetSecuritiesStorage:
                    return "Промежуточная база. Чтение места хранения";
                case AuditOperationDictionary.StageDB_GetSecuritiesStorages:
                    return "Промежуточная база. Чтение списка мест хранения";
                case AuditOperationDictionary.StageDB_GetBankStorageAccounts:
                    return "Промежуточная база. Чтение списка счетов Банка в месте хранения";
                case AuditOperationDictionary.StageDB_GetClientPositionsMove:
                    return "Промежуточная база. Чтение движений средств по позициям";
                case AuditOperationDictionary.StageDB_GetClientSecuritiesMove:
                    return "Промежуточная база. Чтение движений ЦБ";
                case AuditOperationDictionary.StageDB_GetClientProxies:
                    return "Промежуточная база. Чтение спика доверенностей Клиента";
                case AuditOperationDictionary.StageDB_GetExchangeDocumentsForSign:
                    return "Промежуточная база. Чтение списка документов для обмена из промежуточной базы в ЛКК для подписи";
                case AuditOperationDictionary.StageDB_GetExchangeDocuments:
                    return "Промежуточная база. Чтение списка документов для обмена из промежуточной базы в ЛКК";
                case AuditOperationDictionary.StageDB_GetExchangeDocument:
                    return "Промежуточная база. Чтение документа для импорта в ЛКК";
                case AuditOperationDictionary.StageDB_DeleteExchangeDocument:
                    return "Промежуточная база. Удаление документа из промежуточной БД";
                case AuditOperationDictionary.StageDB_GetClientCashMove:
                    return "Промежуточная база. Чтение движений денежных средств Клиента";
                case AuditOperationDictionary.StageDB_GetClientQuestionnaireInfo:
                    return "Чтение анкетных данных Клиента";
                case AuditOperationDictionary.Auth:
                    return "Авторизация";

                    //Services

                case AuditOperationDictionary.Services_ActivateTasks:
                    return "Активация задач";
                case AuditOperationDictionary.Services_Delay:
                    return "Ожидание следующего такта";
                case AuditOperationDictionary.Services_CheckDocsForImport:
                    return "Импорт документов";
                case AuditOperationDictionary.Services_SheduleCreateProcess:
                    return "Создание процессов по расписанию";
                case AuditOperationDictionary.Services_NotifyExpiredTasks:
                    return "Создание уведомлений для истекших процессов";
                case AuditOperationDictionary.Services_ComposeNotifications:
                    return "Сборка уведомлений";
                case AuditOperationDictionary.Services_SendEmailNotifications:
                    return "Отправка email уведомлений";
                case AuditOperationDictionary.Services_SendWebNotifications:
                    return "Отправка Web уведомлений";
                case AuditOperationDictionary.Services_DropOldSessions:
                    return "Уведомление и закрытие старых сессий";
                case AuditOperationDictionary.Services_NotifyAuthorityDead:
                    return "Уведомление и закрытие старых полномочий работы";
                case AuditOperationDictionary.Services_NotifyCertificateDead:
                    return "Уведомление и закрытие старых сертификатов";
                case AuditOperationDictionary.Services_ReadEmailSettings:
                    return "Чтение настроек отсылки Email уведомлений";

                default:
                    throw new ArgumentOutOfRangeException("auditOperationType",auditOperationType.ToString());
            }
        }

        private string getAuditObjectName(AuditObjectDictionary auditObjectType)
        {
            switch (auditObjectType)
            {
                case AuditObjectDictionary.Document:
                    return "Документ";
                case AuditObjectDictionary.AuthorizationPolicySettings:
                    return "Настройки политики авторизации";
                case AuditObjectDictionary.CaSettings:
                    return "Настройки центра проверки сертификатов";
                case AuditObjectDictionary.Calendar:
                    return "Календарь";
                case AuditObjectDictionary.Certificate:
                    return "Сертификат";
                case AuditObjectDictionary.CertificateRequest:
                    return "Запрос на создание сертификата";
                case AuditObjectDictionary.ClientsGroup:
                    return "Группа Клиентов";
                case AuditObjectDictionary.CommonSetting:
                    return "Общие Настройки";
                case AuditObjectDictionary.CyclesSettings:
                    return "Настройки Служб сервера";
                case AuditObjectDictionary.DocumentAttachments:
                    return "Прикрепленные к документам файлы";
                case AuditObjectDictionary.DocumentPrintTemplate:
                    return "Шаблон печати документа";
                case AuditObjectDictionary.DocumentProcessTask:
                    return "Задача процесса обработка документа";
                case AuditObjectDictionary.DocumentProcessTemplate:
                    return "Шаблон процесса обработки документа";
                case AuditObjectDictionary.DocumentProcessTemplateStage:
                    return "Шаблон задачи процесса обработки документов";
                case AuditObjectDictionary.DocumentType:
                    return "Тип документа";
                case AuditObjectDictionary.EmailSmtpSettings:
                    return "Настройки отправки email";
                case AuditObjectDictionary.EventSubscribes:
                    return "Подписка на события";
                case AuditObjectDictionary.IncomeDocumentNumber:
                    return "Номер входящего документа";
                case AuditObjectDictionary.NotificationTemplate:
                    return "Шаблон уведомления";
                case AuditObjectDictionary.NotificationType:
                    return "Тип уведомления";
                case AuditObjectDictionary.NotificationMessageTemplate:
                    return "Шаблон уведомления";
                case AuditObjectDictionary.OutcomeDocumentNumber:
                    return "Номер исходящего документа";
                case AuditObjectDictionary.Password:
                    return "Пароль";
                case AuditObjectDictionary.Permission:
                    return "Разрешение";
                case AuditObjectDictionary.Role:
                    return "Роль";
                case AuditObjectDictionary.Session:
                    return "Сессия";
                case AuditObjectDictionary.Shedule:
                    return "Расписание";
                case AuditObjectDictionary.StageDBSettings:
                    return "Настройки доступа к промежуточной базе";
                case AuditObjectDictionary.SystemLog:
                    return "Лог";
                case AuditObjectDictionary.User:
                    return "Пользователь";
                case AuditObjectDictionary.UserGroup:
                    return "Группа пользователей";
                case AuditObjectDictionary.UserSetting:
                    return "Пользовательские настройки";
                case AuditObjectDictionary.Visa:
                    return "Подпись документа";
                case AuditObjectDictionary.Notification:
                    return "Уведомление";
                default:
                    throw new ArgumentOutOfRangeException("auditObjectType", auditObjectType.ToString());
            }
        }
        
        #endregion Audit

        #region AuditService

        public void AuditServiceAction(ServicesDictionary serviceId, ServiceActionsDictionaty serviceActionId, Guid auditThreadId, string info = null)
        {
            AuditServiceActionInner(serviceId, (AuditOperationDictionary) serviceActionId,
                             null,
                             auditThreadId,
                             info);
        }

        private void AuditServiceActionInner(ServicesDictionary serviceId,
                                      AuditOperationDictionary serviceActionId,
                                      AuditObjectDictionary? auditObjectDictionary,
                                      Guid auditThreadId,
                                      string comment = "",
                                      IEnumerable<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null)
        {
            var auditIndexKey = new AuditIndexKey(serviceActionId, auditObjectDictionary);
            if (AuditIndex.ContainsKey(auditIndexKey))
            {
                var time = DateTime.Now;
                
                if (AuditIndex[auditIndexKey].LogAble)
                {
                    LogServiceAudit(time,
                                    serviceId,
                                    serviceActionId,
                                    auditObjectDictionary,
                                    auditThreadId,
                                    comment,
                                    auditInfo);
                }
            }
            else
            {
                throw new ApplicationException(string.Format("Аудит действия {0} над объектом {1} не поддерживается", serviceActionId, auditObjectDictionary));
            }
        }
        
        private void LogServiceAudit(
            DateTime operationDateTime,
            ServicesDictionary serviceId,
            AuditOperationDictionary actionType,
            AuditObjectDictionary? auditObject,
            Guid auditThreadId,
            string comment = "", IEnumerable<KeyValuePair<AuditInfoKeyDictionary, string>> auditInfo = null)
        {
            string logInfo = string.Format(
                "@@@ Time=\"{0}\",Service=\"{1}\",CorrelationId=\"{2}\",AuditOperationType=\"{4}\",AuditOperationTypeName=\"{3}\"{4},{5}{6}",
                operationDateTime.ToString("G"),
                getServiceName(serviceId),
                auditThreadId,
                getAuditOperationName(actionType),
                actionType.ToString(),
                auditObject != null
                    ? string.Format(",AuditObjectType=\"{0}\",AuditObjectTypeName=\"{1}\"", auditObject.Value.ToString(), getAuditObjectName(auditObject.Value))
                    : "",
                string.IsNullOrWhiteSpace(comment) ? "" : string.Format(",Comment=\"{0}\"", comment));

            if (auditInfo != null)
                logInfo = auditInfo.Aggregate(logInfo, (current, aInfo) =>
                        string.Format("{0},AuditInfoType =\"{1}\",AuditInfoTypeName=\"{2}\",AuditInfoTypeValue=\"{3}\"", current, aInfo.Key, getAuditInfoKeyName(aInfo.Key), aInfo.Value));

            log.Info(logInfo);
        }
        
        private string getServiceName(ServicesDictionary serviceId)
        {
            switch (serviceId)
            {
                case ServicesDictionary.ActivateTasksSendNotifications:
                    return "Служба обработки задач ЛКК (TasksHandlerService)";
                case ServicesDictionary.CheckDocsForImport:
                    return "Служба проверки наличия отчетов для импорта (CheckDocsForImportService)";
                case ServicesDictionary.ComposeNotifications:
                    return "Служба сборки уведомлений ЛКК (ComposeNotificationsService)";
                case ServicesDictionary.DropSessions:
                    return "Служба мониторинга сессий ЛКК( DropSessionsService)";
                case ServicesDictionary.ExpiredTasksSearch:
                    return "Служба отслеживания просроченных задач (ExpiredTasksSearch)";
                case ServicesDictionary.NotifyAuthorityDead:
                    return "Служба завершения полномочий работы ЛКК (NotifyAuthorityDeadService)";
                case ServicesDictionary.NotifyCertificateDead:
                    return "Служба уведомления об окончании действия сертификата ЛКК (NotifyCertificateDeadService)";
                case ServicesDictionary.SendEmailNotifications:
                    return "Служба отсылки Email уведомлений ЛКК (EmailNotificationService)";
                case ServicesDictionary.SendWebNotifications:
                    return "Служба отсылки Web уведомлений (SendWebNotifications)";
                case ServicesDictionary.SheduleCreateProcess:
                    return "Сервис заданий по расписанию ЛКК (SheduleService)";
                default:
                    throw new ArgumentOutOfRangeException("ServicesDictionary", serviceId.ToString());
            }
        }
        #endregion AuditService
    }

    public class EqualityComparerIPRange : IEqualityComparer<IPRange>
    {
        #region IEqualityComparer<IPRange> Members

        public bool Equals(IPRange x,
                           IPRange y)
        {
            return (x.IP.ToLower() == y.IP.ToLower() &&
                    ((string.IsNullOrEmpty(x.Mask) && string.IsNullOrEmpty(x.Mask)) || (x.Mask.ToLower() == y.Mask.ToLower())) &&
                    x.UserId == y.UserId);
        }

        public int GetHashCode(IPRange obj)
        {
            return obj.IP.GetHashCode() + (string.IsNullOrEmpty(obj.Mask)
                                                   ? 0
                                                   : obj.Mask.GetHashCode()) + obj.UserId.GetHashCode();
        }

        #endregion
    }

    /// <summary>
    ///     Внутренний клас для сортировки диапозонов  IP адресов с одинаковыми масками
    /// </summary>
    internal class IPArrayList
    {
        private readonly ArrayList ipNumList = new ArrayList();
        private readonly uint ipmask;
        private bool isSorted;

        /// <summary>
        ///     Constructor that sets the mask for the list
        /// </summary>
        public IPArrayList(uint mask)
        {
            ipmask = mask;
        }

        /// <summary>
        ///     The IP mask for this list of IP numbers
        /// </summary>
        public uint Mask
        {
            get { return ipmask; }
        }

        /// <summary>
        ///     Add a new IP numer (range) to the list
        /// </summary>
        public void Add(uint IPNum)
        {
            isSorted = false;
            ipNumList.Add(IPNum & ipmask);
        }

        /// <summary>
        ///     Checks if an IP number is within the ranges included by the list
        /// </summary>
        public bool Check(uint IPNum)
        {
            bool found = false;
            if (ipNumList.Count > 0)
            {
                if (!isSorted)
                {
                    ipNumList.Sort();
                    isSorted = true;
                }
                IPNum = IPNum & ipmask;
                if (ipNumList.BinarySearch(IPNum) >= 0)
                    found = true;
            }
            return found;
        }

        /// <summary>
        ///     Clears the list
        /// </summary>
        public void Clear()
        {
            ipNumList.Clear();
            isSorted = false;
        }

        /// <summary>
        ///     The ToString is overriden to generate a list of the IP numbers
        /// </summary>
        public override string ToString()
        {
            var buf = new StringBuilder();
            foreach (uint ipnum in ipNumList)
            {
                if (buf.Length > 0)
                    buf.Append("\r\n");
                buf.Append(((int) ipnum & 0xFF000000) >> 24)
                   .Append('.');
                buf.Append(((int) ipnum & 0x00FF0000) >> 16)
                   .Append('.');
                buf.Append(((int) ipnum & 0x0000FF00) >> 8)
                   .Append('.');
                buf.Append(((int) ipnum & 0x000000FF));
            }
            return buf.ToString();
        }
    }

    /// <summary>
    ///     Список IP адресов
    /// </summary>
    public class IPList
    {
        private readonly ArrayList ipRangeList = new ArrayList();
        private readonly SortedList maskList = new SortedList();
        private readonly ArrayList usedList = new ArrayList();

        public IPList()
        {
            // Initialize IP mask list and create IPArrayList into the ipRangeList
            uint mask = 0x00000000;
            for (int level = 1; level < 33; level++)
            {
                mask = (mask >> 1) | 0x80000000;
                maskList.Add(mask,
                             level);
                ipRangeList.Add(new IPArrayList(mask));
            }
        }

        // Parse a String IP address to a 32 bit unsigned integer
        // We can't use System.Net.IPAddress as it will not parse
        // our masks correctly eg. 255.255.0.0 is pased as 65535 !
        private uint parseIP(string IPNumber)
        {
            uint res = 0;
            string[] elements = IPNumber.Split(new[]
                                               {
                                                       '.'
                                               });
            if (elements.Length == 4)
            {
                res = (uint) Convert.ToInt32(elements[0]) << 24;
                res += (uint) Convert.ToInt32(elements[1]) << 16;
                res += (uint) Convert.ToInt32(elements[2]) << 8;
                res += (uint) Convert.ToInt32(elements[3]);
            }
            return res;
        }

        /// <summary>
        ///     Add a single IP number to the list as a string, ex. 10.1.1.1
        /// </summary>
        public void Add(string ipNumber)
        {
            Add(parseIP(ipNumber));
        }

        /// <summary>
        ///     Add a single IP number to the list as a unsigned integer, ex. 0x0A010101
        /// </summary>
        public void Add(uint ip)
        {
            ((IPArrayList) ipRangeList[31]).Add(ip);
            if (!usedList.Contains(31))
            {
                usedList.Add(31);
                usedList.Sort();
            }
        }

        /// <summary>
        ///     Adds IP numbers using a mask for range where the mask specifies the number of
        ///     fixed bits, ex. 172.16.0.0 255.255.0.0 will add 172.16.0.0 - 172.16.255.255
        /// </summary>
        public void Add(string ipNumber,
                        string mask)
        {
            Add(parseIP(ipNumber),
                parseIP(mask));
        }

        /// <summary>
        ///     Adds IP numbers using a mask for range where the mask specifies the number of
        ///     fixed bits, ex. 0xAC1000 0xFFFF0000 will add 172.16.0.0 - 172.16.255.255
        /// </summary>
        public void Add(uint ip,
                        uint umask)
        {
            object Level = maskList[umask];
            if (Level != null)
            {
                ip = ip & umask;
                ((IPArrayList) ipRangeList[(int) Level - 1]).Add(ip);
                if (!usedList.Contains((int) Level - 1))
                {
                    usedList.Add((int) Level - 1);
                    usedList.Sort();
                }
            }
        }

        /// <summary>
        ///     Adds IP numbers using a mask for range where the mask specifies the number of
        ///     fixed bits, ex. 192.168.1.0/24 which will add 192.168.1.0 - 192.168.1.255
        /// </summary>
        public void Add(string ipNumber,
                        int maskLevel)
        {
            Add(parseIP(ipNumber),
                (uint) maskList.GetKey(maskList.IndexOfValue(maskLevel)));
        }

        /// <summary>
        ///     Adds IP numbers using a from and to IP number. The method checks the range and
        ///     splits it into normal ip/mask blocks.
        /// </summary>
        public void AddRange(string fromIP,
                             string toIP)
        {
            AddRange(parseIP(fromIP),
                     parseIP(toIP));
        }

        /// <summary>
        ///     Adds IP numbers using a from and to IP number. The method checks the range and
        ///     splits it into normal ip/mask blocks.
        /// </summary>
        public void AddRange(uint fromIP,
                             uint toIP)
        {
            // If the order is not asending, switch the IP numbers.
            if (fromIP > toIP)
            {
                uint tempIP = fromIP;
                fromIP = toIP;
                toIP = tempIP;
            }
            if (fromIP == toIP)
            {
                Add(fromIP);
            }
            else
            {
                uint diff = toIP - fromIP;
                int diffLevel = 1;
                uint range = 0x80000000;
                if (diff < 256)
                {
                    diffLevel = 24;
                    range = 0x00000100;
                }
                while (range > diff)
                {
                    range = range >> 1;
                    diffLevel++;
                }
                var mask = (uint) maskList.GetKey(maskList.IndexOfValue(diffLevel));
                uint minIP = fromIP & mask;
                if (minIP < fromIP)
                    minIP += range;
                if (minIP > fromIP)
                {
                    AddRange(fromIP,
                             minIP - 1);
                    fromIP = minIP;
                }
                if (fromIP == toIP)
                {
                    Add(fromIP);
                }
                else
                {
                    if ((minIP + (range - 1)) <= toIP)
                    {
                        Add(minIP,
                            mask);
                        fromIP = minIP + range;
                    }
                    if (fromIP == toIP)
                    {
                        Add(toIP);
                    }
                    else
                    {
                        if (fromIP < toIP)
                            AddRange(fromIP,
                                     toIP);
                    }
                }
            }
        }

        /// <summary>
        ///     Checks if an IP number is contained in the lists, ex. 10.0.0.1
        /// </summary>
        public bool CheckNumber(string ipNumber)
        {
            return CheckNumber(parseIP(ipNumber));
            ;
        }

        /// <summary>
        ///     Checks if an IP number is contained in the lists, ex. 0x0A000001
        /// </summary>
        public bool CheckNumber(uint ip)
        {
            bool found = false;
            int i = 0;
            while (!found && i < usedList.Count)
            {
                found = ((IPArrayList) ipRangeList[(int) usedList[i]]).Check(ip);
                i++;
            }
            return found;
        }

        /// <summary>
        ///     Clears all lists of IP numbers
        /// </summary>
        public void Clear()
        {
            foreach (int i in usedList)
            {
                ((IPArrayList) ipRangeList[i]).Clear();
            }
            usedList.Clear();
        }

        /// <summary>
        ///     Generates a list of all IP ranges in printable format
        /// </summary>
        public override string ToString()
        {
            var buffer = new StringBuilder();
            foreach (int i in usedList)
            {
                buffer.Append("\r\nRange with mask of ")
                      .Append(i + 1)
                      .Append("\r\n");
                buffer.Append(ipRangeList[i]);
            }
            return buffer.ToString();
        }

    }
    
}
