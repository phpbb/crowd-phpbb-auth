/**
 * Copyright 2010 phpBB Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.phpbb.crowd;

import com.atlassian.crowd.directory.RemoteDirectory;
import com.atlassian.crowd.embedded.api.PasswordCredential;
import com.atlassian.crowd.exception.*;
import com.atlassian.crowd.model.*;
import com.atlassian.crowd.model.user.*;
import com.atlassian.crowd.model.group.*;
import com.atlassian.crowd.model.membership.*;
import com.atlassian.crowd.search.query.membership.*;
import com.atlassian.crowd.search.query.entity.*;
import com.atlassian.crowd.search.query.entity.restriction.*;
import com.atlassian.crowd.search.ReturnType;
import com.atlassian.crowd.search.Entity;
import com.atlassian.crowd.embedded.api.SearchRestriction;
import com.atlassian.crowd.util.BoundedCount;

import java.rmi.RemoteException;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.*;

/**
 * The phpBB Directory Server provides an interface to phpBB users and groups.
 *
 * All access is read-only. The data is retrieved through HTTP requests to a
 * special file that has to be dropped into the phpBB root directory.
 */
public class phpBBDirectoryServer implements RemoteDirectory
{
    private static final Logger log = LoggerFactory.getLogger(phpBBDirectoryServer.class);

    private long directoryId;
    private Map<String,String> attributes;

    private String serverUrl;

    /**
    * Constructor of the phpBB Directory Server reads the phpBB board root URL from
    * the environment variable CROWD_PHPBB_ROOT_URL.
    *
    * Make sure to export this variable before starting crowd.
    */
    public phpBBDirectoryServer()
    {
        serverUrl = System.getenv("CROWD_PHPBB_ROOT_URL");
    }

    @Override
    public long getDirectoryId()
    {
        return directoryId;
    }

    @Override
    public void setDirectoryId(long directoryId)
    {
        this.directoryId = directoryId;
    }

    public String getName()
    {
        return "phpbbauth";
    }

    @Override
    public String getDescriptiveName()
    {
        return "phpBB Directory Server";
    }

    @Override
    public void setAttributes(Map<String,String> attributes)
    {
        this.attributes = attributes;
    }

    @Override
    public Set<String> getValues(String name)
    {
        log.info("crowd-phpbbauth-plugin: getAttributes: " + name);
        return new HashSet<String>();
    }

    @Override
    public String getValue(String name)
    {
        log.info("crowd-phpbbauth-plugin: getAttribute: " + name);
        return "";
    }

    @Override
    public Set<String> getKeys()
    {
        log.info("crowd-phpbbauth-plugin: getAttributeNames");
        return new HashSet<String>();
    }

    public boolean hasAttribute(String name)
    {
        log.info("crowd-phpbbauth-plugin: hasAttribute: " + name);
        return false;
    }

    @Override
    public boolean isEmpty()
    {
        return true;
    }

    @Override
    public User findUserByName(String name)
        throws UserNotFoundException
    {
        log.info("crowd-phpbbauth-plugin: findUserByName: " + name);

        SearchRestriction searchRestriction = new TermRestriction(new PropertyImpl("name", String.class), MatchMode.EXACTLY_MATCHES, name);
        UserQuery query = new UserQuery(User.class, searchRestriction, 0, 1); // start, max

        List list = new ArrayList<UserTemplate>();
        searchEntities("searchUsers", new UserEntityCreator(getDirectoryId()), query, list);

        if (list.size() == 0)
        {
            throw new UserNotFoundException(name);
        }

        return (User) list.get(0);

    }

    @Override
    public User findUserByExternalId(String externalId)
        throws UserNotFoundException, OperationFailedException
    {
        log.info("crowd-phpbbauth-plugin: findUserByExternalId: " + externalId);
        throw new OperationFailedException();
    }

    @Override
    public UserWithAttributes findUserWithAttributesByName(String name)
        throws UserNotFoundException, OperationFailedException
    {
        log.info("crowd-phpbbauth-plugin: findUserWithAttributesByName: " + name);

        // no attributes support, so just fake it
        User user = findUserByName(name);

        return (UserWithAttributes) new UserEntityCreator(getDirectoryId()).attachAttributes(user);
    }

    /**
     * Authenticates a user against the phpBB authentication method.
     *
     * Username and password are sent in a urlencoded POST request.
     * The request returns either an error line and an error message
     * or success and the data required to create a UserTemplate
     * object. phpBB still counts login attempts, so brute force is not
     * possible regardless of how this method is used.
     *
     * @param    name        The username.
     * @param    credential  Credential object containing the password.
     *
     * @return               A UserTemplate object, which
     *                       implements the User interface.
     *
     * @throws   InactiveAccountException        Account inactive or login
     *                                           attempts exceeded.
     * @throws   InvalidAuthenticationException  Invalid username or password.
     * @throws   ObjectNotFoundException         Any other errors
     */
    @Override
    public User authenticate(String name, PasswordCredential credential)
        throws UserNotFoundException, InactiveAccountException, InvalidAuthenticationException, ExpiredCredentialException, OperationFailedException
    {
        HashMap<String, String> params = new HashMap<String, String>();
        params.put("action", "authenticate");
        params.put("name", name);
        params.put("credential", credential.getCredential());

        ArrayList<String> result = sendPostRequest(params);

        if (result.size() < 2)
        {
            throw new UserNotFoundException(name);
        }

        log.info("crowd-phpbbauth-plugin: authenticate: " + name);
        log.info("crowd-phpbbauth-plugin: result: " + result.get(0));
        log.info("crowd-phpbbauth-plugin: result: " + result.get(1));

        if (!result.get(0).equals("success"))
        {
            //NOTE: These messages will only appear in Crowd. Jira will ignore this and simply show "Sorry, your username and password are incorrect"
            String error = result.get(1);

            if (error.equals("LOGIN_ERROR_ATTEMPTS"))
            {
                throw new InvalidAuthenticationException("Too many failed logins on forum.");
            }

            if (error.equals("ACTIVE_ERROR"))
            {
                throw new InactiveAccountException("Account is inactive.");
            }

            throw new InvalidAuthenticationException("Username or password are incorrect.");
        }

        UserEntityCreator entityCreator = new UserEntityCreator(getDirectoryId());
        try
        {
            User user = (User) entityCreator.fromLine(result.get(1));
            return user;
        }
        catch (ObjectNotFoundException e)
        {
            throw new UserNotFoundException(name);
        }
    }

    @Override
    public User addUser(UserTemplate user, PasswordCredential credential)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public UserWithAttributes addUser(UserTemplateWithAttributes user, PasswordCredential credential)
            throws OperationFailedException {
                throw new OperationFailedException();
    }

    @Override
    public User updateUser(UserTemplate user)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public void updateUserCredential(String username, PasswordCredential credential)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public User renameUser(String oldName, String newName)
        throws OperationFailedException, InvalidUserException
    {
        throw new OperationFailedException();
    }

    @Override
    public void storeUserAttributes(String username, Map<String,Set<String>> attributes)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public void removeUserAttributes(String username, String attributeName)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public void removeUser(String name)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public List searchUsers(EntityQuery query)
    {
        log.info("crowd-phpbbauth-plugin: searchUsers");

        List list = new ArrayList<UserTemplate>();
        searchEntities("searchUsers", new UserEntityCreator(getDirectoryId()), query, list);

        return list;
    }

    @Override
    public Group findGroupByName(String name)
        throws GroupNotFoundException
    {
        log.info("crowd-phpbbauth-plugin: findGroupByName: " + name);

        SearchRestriction searchRestriction = new TermRestriction(new PropertyImpl("name", String.class), MatchMode.EXACTLY_MATCHES, name);
        GroupQuery query = new GroupQuery(Group.class, GroupType.GROUP, searchRestriction, 0, 1); // start, max

        List list = new ArrayList<GroupTemplate>();
        searchEntities("searchGroups", new GroupEntityCreator(getDirectoryId()), query, list);

        if (list.size() == 0)
        {
            throw new GroupNotFoundException(name);
        }

        return (Group) list.get(0);
    }

    @Override
    public GroupWithAttributes findGroupWithAttributesByName(String name)
        throws OperationFailedException, GroupNotFoundException
    {
        log.info("crowd-phpbbauth-plugin: findGroupWithAttributesByName: " + name);

        // no attributes support, so just fake it
        Group group = findGroupByName(name);

        return (GroupWithAttributes) new GroupEntityCreator(getDirectoryId()).attachAttributes(group);
    }

    @Override
    public Group addGroup(GroupTemplate group)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public Group updateGroup(GroupTemplate group)
        throws ReadOnlyGroupException
    {
        throw new ReadOnlyGroupException(group.getName());
    }

    @Override
    public Group renameGroup(String oldName, String newName)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public void storeGroupAttributes(String groupName, Map<String,Set<String>> attributes)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public void removeGroupAttributes(String groupName, String attributeName)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public void removeGroup(String name)
        throws ReadOnlyGroupException
    {
        throw new ReadOnlyGroupException(name);
    }

    @Override
    public List searchGroups(EntityQuery query)
    {
        log.info("crowd-phpbbauth-plugin: searchGroups");

        List list = new ArrayList<GroupTemplate>();
        searchEntities("searchGroups", new GroupEntityCreator(getDirectoryId()), query, list);

        return list;
    }

    @Override
    public boolean isUserDirectGroupMember(String username, String groupName)
    {
        log.info("crowd-phpbbauth-plugin: isUserDirectGroupMember: " + username + ", " + groupName);
        EntityCreator creator;
        List list;
        UserQuery userQuery;

        SearchRestriction searchRestrictionUser = new TermRestriction(
            new PropertyImpl("name", String.class),
            MatchMode.EXACTLY_MATCHES,
            username
        );

        SearchRestriction searchRestrictionGroup = new TermRestriction(
            new PropertyImpl("groupname", String.class),
            MatchMode.EXACTLY_MATCHES,
            groupName
        );

        SearchRestriction searchRestriction = new BooleanRestrictionImpl(
            BooleanRestriction.BooleanLogic.AND,
            searchRestrictionUser,
            searchRestrictionGroup
        );

        list = new ArrayList<String>();
        userQuery = new UserQuery(String.class, searchRestriction, 0, 1); // start, max

        searchEntities("userMemberships", null, userQuery, list);

        if (list.size() > 0)
        {
            return true;
        }
        return false;
    }

    /**
     * No nested group support, so a group can never be a direct member.
     *
     * @return   Always false.
     */
    @Override
    public boolean isGroupDirectGroupMember(String childGroup, String parentGroup)
    {
        log.info("crowd-phpbbauth-plugin: isGroupDirectGroupMember");
        return false;
    }

    @Override
    public BoundedCount countDirectMembersOfGroup(String groupName, int querySizeHint)
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    @Override
    public void addUserToGroup(String username, String groupName)
        throws ReadOnlyGroupException
    {
        throw new ReadOnlyGroupException(groupName);
    }

    @Override
    public void addGroupToGroup(String childGroup, String parentGroup)
        throws ReadOnlyGroupException
    {
        throw new ReadOnlyGroupException(parentGroup);
    }

    @Override
    public void removeUserFromGroup(String username, String groupName)
        throws ReadOnlyGroupException
    {
        throw new ReadOnlyGroupException(groupName);
    }

    @Override
    public void removeGroupFromGroup(String childGroup, String parentGroup)
        throws MembershipNotFoundException
    {
        throw new MembershipNotFoundException(childGroup, parentGroup);
    }

    @Override
    public List searchGroupRelationships(MembershipQuery query)
    {
        log.info("crowd-phpbbauth-plugin: searchGroupRelationships");

        EntityCreator creator;
        List list;
        EntityQuery entityQuery;
        String action;

        SearchRestriction searchRestriction = new TermRestriction(
            new PropertyImpl("name", String.class),
            MatchMode.EXACTLY_MATCHES,
            query.getEntityNamesToMatch().iterator().next() // We only operate on single search terms, so grab the first
        );

        if (query.getEntityToMatch().getEntityType() != Entity.GROUP)
        {
            action = "userMemberships";
            entityQuery = new UserQuery(User.class, searchRestriction, query.getStartIndex(), query.getMaxResults());
        }
        else
        {
            action = "groupMembers";
            entityQuery = new GroupQuery(Group.class, GroupType.GROUP, searchRestriction, query.getStartIndex(), query.getMaxResults());
        }

        if (query.getEntityToReturn().getEntityType() == Entity.GROUP)
        {
            creator = new GroupEntityCreator(getDirectoryId());
            list = new ArrayList<GroupTemplate>();
        }
        else
        {
            creator = new UserEntityCreator(getDirectoryId());
            list = new ArrayList<UserTemplate>();
        }

        log.info("crowd-phpbbauth-plugin: entity to return: " + query.getEntityToReturn().toString());
        log.info("crowd-phpbbauth-plugin: returnType: " + query.getReturnType().toString());

        searchEntities(action, creator, entityQuery, list);

        if (query.getReturnType() == String.class)
        {
            ArrayList<String> stringList = new ArrayList<String>();
            for (Iterator it = list.iterator(); it.hasNext(); )
            {
                Object x = it.next();
                if (x instanceof GroupTemplate)
                {
                    stringList.add(((GroupTemplate) x).getName());
                }
                else
                {
                    stringList.add(((UserTemplate) x).getName());
                }
            }
            return stringList;
        }

        return list;
    }

    @Override
    public void testConnection()
        throws OperationFailedException
    {
        // could implement a simple http request here
    }

    @Override
    public void expireAllPasswords()
        throws OperationFailedException
    {
        throw new OperationFailedException();
    }

    /**
     * phpBB does not support nested Groups
     *
     * @return   Always false.
     */
    @Override
    public boolean supportsNestedGroups()
    {
        return false;
    }

    @Override
    public boolean supportsPasswordExpiration()
    {
        return false;
    }

    @Override
    public boolean supportsSettingEncryptedCredential()
    {
        return false;
    }

    @Override
    public RemoteDirectory getAuthoritativeDirectory()
    {
        return (RemoteDirectory) this;
    }

    @Override
    public Iterable<Membership> getMemberships()
        throws OperationFailedException
    {
        log.info("crowd-phpbbauth-plugin: getMemberships");
        throw new OperationFailedException();
    }

    @Override
    public boolean isRolesDisabled()
    {
        return true;
    }

    @Override
    public boolean supportsInactiveAccounts()
    {
        return true;
    }

    protected void searchEntities(String action, EntityCreator entityCreator, EntityQuery query, List list)
    {
        HashMap<String, String> params = new HashMap<String, String>();
        params.put("action", action);
        params.put("start", new Integer(query.getStartIndex()).toString());
        params.put("max", new Integer(query.getMaxResults()).toString());

        String returnType = (query.getReturnType() == String.class) ? "NAME" : query.getReturnType().toString();

        if (query.getReturnType() == User.class || query.getReturnType() == Group.class)
        {
            returnType = "ENTITY";
        }

        params.put("returnType", returnType); // NAME or ENTITY

        SearchRestriction restriction = query.getSearchRestriction();
        if (restriction != null)
        {
            params.put("restriction", restrictionToJson(restriction));
        }

        ArrayList<String> result = sendPostRequest(params);
        if (result.size() > 0)
        {
            log.info("crowd-phpbbauth-plugin: returnType: " + returnType);
            log.info("crowd-phpbbauth-plugin: result: " + result.get(0));
        }

        for (Iterator it = result.iterator(); it.hasNext(); )
        {
            String line = (String) it.next();

            if (query.getReturnType() != String.class)
            {
                try
                {
                    list.add(entityCreator.fromLine(line));
                }
                catch (ObjectNotFoundException e)
                {
                }
            }
            else
            {
                list.add(line);
            }
        }
    }

    protected String restrictionToJson(SearchRestriction restriction)
    {
        if (restriction instanceof NullRestriction)
        {
            return "null";
        }
        else if (restriction instanceof TermRestriction)
        {
            TermRestriction termRestriction = (TermRestriction) restriction;
            String value = "";
            if (termRestriction.getValue() != null)
            {
                value = termRestriction.getValue().toString();
            }

            return "{\"mode\": \"" + termRestriction.getMatchMode().toString() + "\", \"property\": \"" + escape(termRestriction.getProperty().getPropertyName()) + "\", \"value\": \"" + escape(value) + "\"}";
        }
        else if (restriction instanceof BooleanRestrictionImpl)
        {
            BooleanRestrictionImpl multiTermRestriction = (BooleanRestrictionImpl) restriction;
            Collection<SearchRestriction> restrictions = multiTermRestriction.getRestrictions();

            String result = "{\"boolean\": \"" + multiTermRestriction.getBooleanLogic().toString() + "\", \"terms\": [";

            for (Iterator it = restrictions.iterator(); it.hasNext(); )
            {
                result += restrictionToJson((SearchRestriction) it.next());

                if (it.hasNext())
                {
                    result += ", ";
                }
            }
            result += "]}";

            return result;
        }

        return "null";
    }

    /**
     * Escapes a string for use in a JSON string.
     *
     * @param    source  The unescaped input string.
     *
     * @return           Source string with backslashes and quotes escaped.
     */
    protected String escape(String source)
    {
        String result;

        // double backslashes because of java string, and those doubled again
        // because it's a regex. so this is really just
        // (1) \ => \\
        // (2) " => \"
        result = source.replaceAll("\\\\", "\\\\\\\\");
        result = result.replaceAll("\"", "\\\\\\\"");

        return result;
    }

    protected ArrayList<String> sendPostRequest(Map<String, String> params)
    {
        String data = "";
        ArrayList<String> result = new ArrayList<String>();

        try
        {
            for (Map.Entry<String, String> entry : params.entrySet())
            {
                data += URLEncoder.encode(entry.getKey(), "UTF-8");
                data += "=";
                data += URLEncoder.encode(entry.getValue(), "UTF-8");
                data += "&";
            }
            String api_url = serverUrl;
            if (serverUrl.charAt(serverUrl.length() - 1) != '/')
            {
                api_url += "/";
            }

            URL url = new URL(api_url + "auth_api.php");

            URLConnection connection = url.openConnection();
            connection.setDoOutput(true);

            OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream());

            writer.write(data);
            writer.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null)
            {
                result.add(line);
            }

            writer.close();
            reader.close();
        }
        catch (Exception e)
        {
            log.error("crowd-phpbbauth-plugin: HTTP request: " + e);
        }

        return result;
    }
}
