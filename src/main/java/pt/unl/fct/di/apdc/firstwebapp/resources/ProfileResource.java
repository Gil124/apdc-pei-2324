package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import com.google.cloud.datastore.StructuredQuery.*;
import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.ProfileData;
import pt.unl.fct.di.apdc.firstwebapp.util.UserData;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

@Path("/profile")
@Produces(MediaType.APPLICATION_JSON)
public class ProfileResource {
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

    private final Gson g = new Gson();

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();


    public ProfileResource() {}


    @PUT
    @Path("/role")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeRole(@HeaderParam("tokenId") String tokenId, @HeaderParam("username") String username, @HeaderParam("userToChange") String userToChange, ProfileData data) {
        LOG.fine("Attempt to change role by: " + tokenId);

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity user = datastore.get(userKey);

        if (user==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid username: " + username).build();
        }

        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("Token").newKey(tokenId);
        Entity key = datastore.get(tokenKey);

        if(key==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid tokenId: " + tokenKey.getName()).build();
        } else if (key.getLong("expirationData") <= System.currentTimeMillis()) {
            datastore.delete(tokenKey);
            return Response.status((Response.Status.FORBIDDEN)).entity("expired tokenId: " + tokenKey.getName()).build();
        }

        Key userToChangeKey = datastore.newKeyFactory().setKind("User").newKey(userToChange);
        Entity userToChangeData = datastore.get(userToChangeKey);

        if (userToChangeData == null) { return Response.status((Response.Status.FORBIDDEN)).entity("invalid username of user to change: " + userToChange).build(); }

        String currentRole = userToChangeData.getString("role");

        String userRole = user.getString("role");
        if (userRole.equals("USER") || userRole.equals("GBO")) {
            return Response.status((Response.Status.FORBIDDEN)).entity("user " + username + " does not have permissions for this function").build();
        } else if (userRole.equals("GA")) {
            if (!currentRole.equals("USER") && !currentRole.equals("GBO")) { return Response.status((Response.Status.FORBIDDEN)).entity("user " + username + " does not have permissions to change this user data: " + userToChange).build(); }
            if (!data.role.equals("USER") && !data.role.equals("GBO")) { return Response.status((Response.Status.FORBIDDEN)).entity("user " + username + " does not have permissions to change users to this role: " + data.role).build(); }
        }

        datastore.update(Entity.newBuilder(userToChangeKey)
                .set("email", userToChangeData.getString("email"))
                .set("password", userToChangeData.getString("password"))
                .set("name", userToChangeData.getString("name"))
                .set("phone_number", userToChangeData.getString("phone_number"))
                .set("role", data.role)
                .set("state", userToChangeData.getBoolean("state"))
                .build());

        return Response.ok().build();
    }

    @PUT
    @Path("/state")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeState(@HeaderParam("tokenId") String tokenId, @HeaderParam("username") String username, @HeaderParam("userToChange") String userToChange, ProfileData data) {
        LOG.fine("Attempt to change state by: " + tokenId);

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity user = datastore.get(userKey);

        if (user==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid username: " + username).build();
        }

        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("Token").newKey(tokenId);
        Entity key = datastore.get(tokenKey);

        if(key==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid tokenId: " + tokenKey.getName()).build();
        } else if (key.getLong("expirationData") <= System.currentTimeMillis()) {
            datastore.delete(tokenKey);
            return Response.status((Response.Status.FORBIDDEN)).entity("expired tokenId: " + tokenKey.getName()).build();
        }

        Key userToChangeKey = datastore.newKeyFactory().setKind("User").newKey(userToChange);
        Entity userToChangeData = datastore.get(userToChangeKey);

        if (userToChangeData == null) { return Response.status((Response.Status.FORBIDDEN)).entity("invalid username of user to change: " + userToChange).build(); }

        String userRole = user.getString("role");
        String userToChangeRole = userToChangeData.getString("role");
        if (userRole.equals("USER")) { return Response.status((Response.Status.FORBIDDEN)).entity("user " + username + " does not have permissions for this function").build(); }
        if (userRole.equals("GBO") && !userToChangeRole.equals("USER")) { return Response.status((Response.Status.FORBIDDEN)).entity("user " + username + " does not have permissions to change users of this role: " + userToChangeRole).build(); }
        if (userRole.equals("GA") && (userToChangeRole.equals("GA") || userToChangeRole.equals("SU"))) { return Response.status((Response.Status.FORBIDDEN)).entity("user " + username + " does not have permissions to change users of this role: " + userToChangeRole).build();}

        datastore.update(Entity.newBuilder(userToChangeKey)
                .set("email", userToChangeData.getString("email"))
                .set("password", userToChangeData.getString("password"))
                .set("name", userToChangeData.getString("name"))
                .set("phone_number", userToChangeData.getString("phone_number"))
                .set("role", userToChangeData.getString("role"))
                .set("state", data.state)
                .build());

        return Response.ok().build();
    }

    @DELETE
    @Path("/remove")
    public Response removeUser(@HeaderParam("tokenId") String tokenId, @HeaderParam("username") String username, @HeaderParam("userToRemove") String userToRemove) {
        LOG.fine("Attempt to remove an user by: " + tokenId);

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity user = datastore.get(userKey);

        if (user==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid username: " + username).build();
        }

        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("Token").newKey(tokenId);
        Entity key = datastore.get(tokenKey);

        if(key==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid tokenId: " + tokenKey.getName()).build();
        } else if (key.getLong("expirationData") <= System.currentTimeMillis()) {
            datastore.delete(tokenKey);
            return Response.status((Response.Status.FORBIDDEN)).entity("expired tokenId: " + tokenKey.getName()).build();
        }

        Key userToRemoveKey = datastore.newKeyFactory().setKind("User").newKey(userToRemove);
        Entity userToRemoveData = datastore.get(userToRemoveKey);

        if (userToRemoveData == null) { return Response.status((Response.Status.FORBIDDEN)).entity("invalid username of user to change: " + userToRemove).build(); }

        String userRole = user.getString("role");
        String userToRemoveRole = userToRemoveData.getString("role");

        if (userRole.equals("USER") && !username.equals(userToRemove)) { return Response.status((Response.Status.FORBIDDEN)).entity("user " + username + " does not have permissions for this function").build(); }
        if (userRole.equals("GBO")) { return Response.status((Response.Status.FORBIDDEN)).entity("GBO " + username + " does not have permissions for this function").build(); }
        if (userRole.equals("GA") && (userToRemoveRole.equals("GA") || userToRemoveRole.equals("SU"))) { return Response.status((Response.Status.FORBIDDEN)).entity("GA " + username + " does not have permissions for this function").build(); }

        datastore.delete(userToRemoveKey);

        Query<Key> query = Query.newKeyQueryBuilder().setKind("Token").setFilter(PropertyFilter.hasAncestor(userToRemoveKey)).build();
        QueryResults<Key> results = datastore.run(query);

        while (results.hasNext()) {
            datastore.delete(results.next());
        }

        return Response.ok().build();
    }

    @GET
    @Path("/list")
    public Response listUsers(@HeaderParam("tokenId") String tokenId, @HeaderParam("username") String username) {
        LOG.fine("Attempt to list users by: " + tokenId);

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity user = datastore.get(userKey);

        if (user==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid username: " + username).build();
        }

        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("Token").newKey(tokenId);
        Entity key = datastore.get(tokenKey);

        if(key==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid tokenId: " + tokenKey.getName()).build();
        } else if (key.getLong("expirationData") <= System.currentTimeMillis()) {
            datastore.delete(tokenKey);
            return Response.status((Response.Status.FORBIDDEN)).entity("expired tokenId: " + tokenKey.getName()).build();
        }

        Query<Key> query;
        String userRole = user.getString("role");
        if (userRole.equals("User")) { query = Query.newKeyQueryBuilder().setKind("User").setFilter(CompositeFilter.and(PropertyFilter.eq("role", "USER"), PropertyFilter.eq("state", true))).build(); }
        else if (userRole.equals("GBO")) { query = Query.newKeyQueryBuilder().setKind("User").setFilter(PropertyFilter.eq("role", "USER")).build(); }
        else if (userRole.equals("GA")) { query = Query.newKeyQueryBuilder().setKind("User").setFilter(PropertyFilter.neq("role", "SU")).build(); }
        else { query = Query.newKeyQueryBuilder().setKind("User").build(); }

        List<UserData> users = new ArrayList<>();
        QueryResults<Key> results = datastore.run(query);
        while (results.hasNext()) {
            Key result = results.next();
            Entity resultUser = datastore.get(result);
            users.add(new UserData(result.getName(),resultUser.getString("email"), resultUser.getString("name"), resultUser.getString("phone_number")));
        }


        return  Response.ok(g.toJson(users)).build();
    }

    @PUT
    @Path("/attributes")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeAttributes(@HeaderParam("tokenId") String tokenId, @HeaderParam("username") String username, @HeaderParam("userToChange") String userToChange, UserData data) {
        LOG.fine("Attempt to change attributes by: " + tokenId);

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity user = datastore.get(userKey);

        if (user==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid username: " + username).build();
        }

        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("Token").newKey(tokenId);
        Entity key = datastore.get(tokenKey);

        if(key==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid tokenId: " + tokenKey.getName()).build();
        } else if (key.getLong("expirationData") <= System.currentTimeMillis()) {
            datastore.delete(tokenKey);
            return Response.status((Response.Status.FORBIDDEN)).entity("expired tokenId: " + tokenKey.getName()).build();
        }

        Key userToChangeKey = datastore.newKeyFactory().setKind("User").newKey(userToChange);
        Entity userToChangeData = datastore.get(userToChangeKey);

        if (userToChangeData == null) { return Response.status((Response.Status.FORBIDDEN)).entity("invalid username of user to change: " + userToChange).build(); }

        String userRole = user.getString("role");
        String userToChangeRole = userToChangeData.getString("role");

        if (userRole.equals("USER") && !username.equals(userToChange)) { return Response.status((Response.Status.FORBIDDEN)).entity("user " + username + " does not have permissions for this function").build(); }
        else if (userRole.equals("GBO") && !userToChangeRole.equals("USER")) {  return Response.status((Response.Status.FORBIDDEN)).entity("GBO " + username + " does not have permissions for this function").build(); }
        else if (userRole.equals("GA") && (userToChangeRole.equals("GA")||userToChangeRole.equals("SU"))) { return Response.status((Response.Status.FORBIDDEN)).entity("GA " + username + " does not have permissions for this function").build(); }
        else if (userRole.equals("USER")) { datastore.update(Entity.newBuilder(userToChangeKey)
                .set("email", userToChangeData.getString("email"))
                .set("password", userToChangeData.getString("password"))
                .set("name",userToChangeData.getString("name"))
                .set("phone_number", (data.phoneNumber == null || data.phoneNumber.isEmpty()) ? userToChangeData.getString("phone_number") : data.phoneNumber)
                .set("role", userToChangeData.getString("role"))
                .set("state", userToChangeData.getBoolean("state"))
                .build());
        } else {
            datastore.update(Entity.newBuilder(userToChangeKey)
                    .set("email", (data.email == null || data.email.isEmpty()) ? userToChangeData.getString("email") : data.email)
                    .set("password", userToChangeData.getString("password"))
                    .set("name",(data.name == null || data.name.isEmpty()) ? userToChangeData.getString("name") : data.name)
                    .set("phone_number", (data.phoneNumber == null || data.phoneNumber.isEmpty()) ? userToChangeData.getString("phone_number") : data.phoneNumber)
                    .set("role", userToChangeData.getString("role"))
                    .set("state", userToChangeData.getBoolean("state"))
                    .build());
        }



        return Response.ok().build();
    }

    @DELETE
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response doLogout(@HeaderParam("tokenId") String tokenId, @HeaderParam("username") String username) {
        LOG.fine("Attempt to logout session: " + tokenId);
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity user = datastore.get(userKey);

        if (user==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid username: " + username).build();
        }

        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("Token").newKey(tokenId);
        Entity key = datastore.get(tokenKey);

        if(key==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid tokenId: " + tokenKey.getName()).build();
        }

        datastore.delete(tokenKey);
        return Response.ok().build();
    }

    @PUT
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changePassword(@HeaderParam("tokenId") String tokenId, @HeaderParam("username") String username, ProfileData data) {
        LOG.fine("Attempt to change password");
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity user = datastore.get(userKey);

        if (user==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid username: " + username).build();
        }

        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("Token").newKey(tokenId);
        Entity key = datastore.get(tokenKey);

        if(key==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid tokenId: " + tokenKey.getName()).build();
        } else if (key.getLong("expirationData") <= System.currentTimeMillis()) {
            datastore.delete(tokenKey);
            return Response.status((Response.Status.FORBIDDEN)).entity("expired tokenId: " + tokenKey.getName()).build();
        }

        if(!user.getString("password").equals(DigestUtils.sha512Hex(data.password))) {
                return Response.status(Response.Status.FORBIDDEN).entity("wrong password").build();
        }

        datastore.update(Entity.newBuilder(userKey)
                .set("email", user.getString("email"))
                .set("password", DigestUtils.sha512Hex(data.newPassword))
                .set("name", user.getString("name"))
                .set("phone_number", user.getString("phone_number"))
                .set("role", user.getString("role"))
                .set("state", user.getBoolean("state"))
                .build());

        return Response.ok().build();
    }

    @GET
    @Path("/")
    public Response getToken(@HeaderParam("tokenId") String tokenId, @HeaderParam("username") String username) {
        LOG.fine("Attempt to get session info");
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
        Entity user = datastore.get(userKey);

        if (user==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid username: " + username).build();
        }

        Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("Token").newKey(tokenId);
        Entity key = datastore.get(tokenKey);

        if(key==null) {
            return Response.status((Response.Status.FORBIDDEN)).entity("invalid tokenId: " + tokenKey.getName()).build();
        } else if (key.getLong("expirationData") <= System.currentTimeMillis()) {
            datastore.delete(tokenKey);
            return Response.status((Response.Status.FORBIDDEN)).entity("expired tokenId: " + tokenKey.getName()).build();
        }

        return Response.ok(g.toJson(tokenKey.getName())).build();
    }

}
