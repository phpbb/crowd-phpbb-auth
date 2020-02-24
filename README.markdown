# phpBB Directory Server for Atlassian Crowd
The phpBB Directory Server is in `com.phpbb.crowd.phpBBDirectoryServer`. It implements `com.atlassian.crowd.integration.directory.RemoteDirectory` and can easily be configured as a Directory in Crowd. It does not support any write operations.

## Requirements
* Crowd: 3.3.3+
* phpBB: 3.3.0+

## Installing and Configuring the phpBB Directory Server
Install the Atlassian SDK. Using its `atlas-package` command you can easily build the phpbbauth jar file from the `crowd-phpbb-auth` directory. Place this jar file into `crowd/webapp/WEB-INF/lib`. Make sure to export the `CROWD_PHPBB_ROOT_URL` environment variable, it needs to contain the URL to the root of your phpBB board. Install the phpBB External Authentication API. In Crowd there is a top level Directories tab. Here you can add a new directory. In the "Implementation Class" field you have to fill in "`com.phpbb.crowd.phpBBDirectoryServer`". You should disable all possible write operations in the Permissions tab - even if you don't, all write operations will throw Exceptions. The directory server also does not support any attributes. So even if they show up in the GUI they will not be saved by phpBB.

# phpBB External Authentication API
The API is rather simple for now. It consists of a single PHP file, to be placed in the phpBB root directory. Copy the values from `config.dist.php` into your board's `config.php`. The file replies to a number of POST requests. You can ask it to authenticate a user, password pair against the selected authentication method. You can query the user and group tables individually or join them to retrieve information about group memberships. The interface needs to be cleaned up after which it will make more sense to document all the functionality.