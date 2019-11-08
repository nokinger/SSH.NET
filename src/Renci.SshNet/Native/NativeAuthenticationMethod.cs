using System;
using Renci.SshNet.Messages.Authentication;
using Renci.SshNet.Messages;
using Renci.SshNet.Common;
using System.Threading;

namespace Renci.SshNet
{
    /// <summary>
    /// Provides functionality to perform private key authentication.
    /// </summary>
    public class NativeAuthenticationMethod : AuthenticationMethod, IDisposable
    {
        private AuthenticationResult _authenticationResult = AuthenticationResult.Failure;
        private EventWaitHandle _authenticationCompleted = new ManualResetEvent(false);

        public NativeAuthenticationMethod(string username)
        : base(username)
        {
            
        }

        ~NativeAuthenticationMethod()
        {
            Dispose(false);
        }

        public override string Name
        {
            get { return "publickey"; }
        }

        public override AuthenticationResult Authenticate(Session session)
        {
            session.UserAuthenticationSuccessReceived   += Session_UserAuthenticationSuccessReceived;
            session.UserAuthenticationFailureReceived   += Session_UserAuthenticationFailureReceived;
            session.UserAuthenticationPublicKeyReceived += Session_UserAuthenticationPublicKeyReceived;

            session.RegisterMessage("SSH_MSG_USERAUTH_PK_OK");

            try
            {
                _authenticationCompleted.Reset();

                var message = new RequestMessageNative(ServiceName.Connection, Username);

                message.Sign(session.SessionId);

                session.SendMessage(message);

                session.WaitOnHandle(_authenticationCompleted);

                return _authenticationResult;
            }
            finally
            {
                session.UserAuthenticationSuccessReceived -= Session_UserAuthenticationSuccessReceived;
                session.UserAuthenticationFailureReceived -= Session_UserAuthenticationFailureReceived;
                session.UserAuthenticationPublicKeyReceived -= Session_UserAuthenticationPublicKeyReceived;
                session.UnRegisterMessage("SSH_MSG_USERAUTH_PK_OK");
            }
        }

        private void Session_UserAuthenticationSuccessReceived(object sender, MessageEventArgs<SuccessMessage> e)
        {
            _authenticationResult = AuthenticationResult.Success;

            _authenticationCompleted.Set();
        }

        private void Session_UserAuthenticationFailureReceived(object sender, MessageEventArgs<FailureMessage> e)
        {
            if (e.Message.PartialSuccess)
                _authenticationResult = AuthenticationResult.PartialSuccess;
            else
                _authenticationResult = AuthenticationResult.Failure;

            //  Copy allowed authentication methods
            AllowedAuthentications = e.Message.AllowedAuthentications;

            _authenticationCompleted.Set();
        }

        private void Session_UserAuthenticationPublicKeyReceived(object sender, MessageEventArgs<PublicKeyMessage> e)
        {
         
            _authenticationCompleted.Set();
        }

        private bool _isDisposed;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed)
                return;

            if (disposing)
            {
                var authenticationCompleted = _authenticationCompleted;
                if (authenticationCompleted != null)
                {
                    _authenticationCompleted = null;
                    authenticationCompleted.Dispose();
                }

                _isDisposed = true;
            }
        }
    }
}
