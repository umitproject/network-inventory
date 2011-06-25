# Copyright (C) 2011 Adriano Monteiro Marques.
#
# Author: Dragos Dena <dragos.dena@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from umit.inventory.server.Module import SubscriberServerModule
from umit.inventory.server.Module import ServerModule
from umit.inventory.server.Notification import NotificationFields

import smtplib
from email.mime.text import MIMEText
import time
import traceback
import string


class EmailSender(ServerModule, SubscriberServerModule):

    # Options
    server_host = 'smtp_server_host'
    server_port = 'smtp_server_port'
    from_addr = 'from_address'
    to_list = 'to_list_addresses'
    login = 'login'
    password = 'password'
    enable_html = 'enable_html'
    enable_ssl = 'enable_ssl'
    enable_tsl = 'enable_starttsl_extension'
    send_for = 'send_for_types'


    def __init__(self, configs, shell):
        ServerModule.__init__(self, configs, shell)

        self.host = str(self.options[EmailSender.server_host])
        self.port = int(self.options[EmailSender.server_port])
        self.from_addr = str(self.options[EmailSender.from_addr])
        self.login = str(self.options[EmailSender.login])
        self.password = str(self.options[EmailSender.password])
        self.enable_html = bool(self.options[EmailSender.enable_html])
        self.send_for_types = self.options[EmailSender.send_for].split(',')
        self.to_list = self.options[EmailSender.to_list].split(',')
        self.enable_ssl = bool(self.options[EmailSender.enable_ssl])
        self.enable_tsl = bool(self.options[EmailSender.enable_tsl])

        
    def get_name(self):
        return 'EmailSender'


    def init_default_settings(self):
        self.options[EmailSender.server_host] = 'smtp.gmail.com'
        self.options[EmailSender.server_port] = 587
        self.options[EmailSender.from_addr] = 'dragosdena2@gmail.com'
        self.options[EmailSender.login] = 'dragosdena2@gmail.com'
        self.options[EmailSender.to_list] = 'dena_dr89@yahoo.com,dragos.dena@gmail.com'
        self.options[EmailSender.password] = 'guestpassword'
        self.options[EmailSender.enable_html] = True
        self.options[EmailSender.send_for] = 'CRITICAL,INFO'
        self.options[EmailSender.enable_ssl] = False
        self.options[EmailSender.enable_tsl] = True


    def receive_notification(self, notification):
        """
        Called when receiving a notification. Will check the type and
        send the email if needed.
        """
        type = notification.fields[NotificationFields.notification_type]
        if type in self.send_for_types:
            email_msg = self.fill_email(notification)
            self.send_email(email_msg)


    def fill_email(self, notification):
        """
        Fills in the email based on the notification fields.
        Returns the message string to be sent trough SMTP.
        """

        # Fill the message with the body depending if we enabled HTML or not.
        msg = None
        if self.enable_html:
            body = EmailContentParser.get_html_body(notification)
            msg = MIMEText(body, 'html')
        else:
            body = EmailContentParser.get_text_body(notification)
            msg = MIMEText(body, 'plain')

        # Fill the other fields of the email
        msg['Subject'] = EmailContentParser.get_subject(notification)
        msg['To'] = ', '.join(self.to_list)
        msg['From'] = self.from_addr

        return msg.as_string()


    def send_email(self, msg):
        """ Does the actual sending the email as configured """
        try:
            server = None
            if self.enable_ssl:
                print self.enable_ssl
                server = smtplib.SMTP_SSL(self.host, self.port)
            else:
                server = smtplib.SMTP(self.host, self.port)

            server.set_debuglevel(1)
            server.ehlo()
            # Won't enable STARTTLS over a SSL connection
            if self.enable_tsl and not self.enable_ssl:
                server.starttls()
            server.login(self.login, self.password)
            server.sendmail(self.from_addr, self.to_list , msg)
            server.quit()
        except:
            traceback.print_exc()
            # TODO log this


    def subscribe(self):
        # Subscribing to all notifications
        self.shell.subscribe(self)



class EmailContentParser:

    inventory_stamp = '******* Umit Inventory Notification *******\n\n'

    @staticmethod
    def get_html_body(notification):
        """ Returns the body of the email in html mode """
        # Get the relevant fields to put in the mail
        hostname = notification.fields[NotificationFields.hostname]
        description = notification.fields[NotificationFields.description]
        protocol = notification.fields[NotificationFields.protocol]
        timestamp = notification.fields[NotificationFields.timestamp]
        description = notification.fields[NotificationFields.description]

        # Generate the actual body
        # Stamp part
        stamp_part = EmailContentParser.html_to_bold(\
                EmailContentParser.inventory_stamp)
        stamp_part = EmailContentParser.html_newlines(stamp_part)

        # Details parts: hostname, protocol, timestamp
        details_part = ''
        details_part += 'Hostname which sent the notification: %s<br/>' %\
                EmailContentParser.html_to_bold(hostname)
        details_part += 'Protocol used to generate the notification: %s<br/>' %\
                EmailContentParser.html_to_bold(protocol)
        details_part += 'Notification was generated at: %s<br/>' %\
                EmailContentParser.html_to_bold(time.ctime(timestamp))
        details_part += '<br/>'
        details_part = EmailContentParser.html_to_paragraph(details_part)

        # Description part
        description_part = ''
        description_part += EmailContentParser.html_to_bold(\
                "Notification description:<br/>")
        description_html = EmailContentParser.html_newlines(description)
        description_part += EmailContentParser.html_to_monospaced(description_html)
        description_part = EmailContentParser.html_to_paragraph(description_part)

        # Merge the 3 parts
        body = stamp_part + details_part + description_part
        return EmailContentParser.html_encapsulate(body)


    @staticmethod
    def get_text_body(notification):
        """ Returns the body of the email in text mode """
        # Get the relevant fields to put in the mail
        hostname = notification.fields[NotificationFields.hostname]
        description = notification.fields[NotificationFields.description]
        protocol = notification.fields[NotificationFields.protocol]
        timestamp = notification.fields[NotificationFields.timestamp]
        description = notification.fields[NotificationFields.description]

        # Generate the actual body
        body = ''
        body += EmailContentParser.inventory_stamp
        body += '* Hostname which sent the notification: %s\n' % hostname
        body += '* Protocol used to generate the notification: %s\n' % protocol
        body += '* Notification was generated at: %s\n' % time.ctime(timestamp)
        body += '\n'

        body += '* Notification description:\n'
        body += description

        return body


    @staticmethod
    def get_subject(notification):
        """ Returns the subject which will be used for this notification """
        notification_type =\
                notification.fields[NotificationFields.notification_type]
        timestamp = notification.fields[NotificationFields.timestamp]
        hostname = notification.fields[NotificationFields.hostname]
        
        return '%s Notification from %s (%d)' % (notification_type,\
                hostname, int(timestamp))


    @staticmethod
    def html_to_bold(s):
        return '<span style="font-weight:bold">%s</span>' % s


    @staticmethod
    def html_encapsulate(s):
        return '<html><head></head><body style="color:black; font-size:12px">\
                %s</body></html>' % s


    @staticmethod
    def html_to_monospaced(s):
        return '<span style="font-family:monospace">%s</span>' % s


    @staticmethod
    def html_to_paragraph(s):
        return '<p>%s</p>' % s


    @staticmethod
    def html_newlines(s):
        return string.replace(s, '\n', '<br/>')