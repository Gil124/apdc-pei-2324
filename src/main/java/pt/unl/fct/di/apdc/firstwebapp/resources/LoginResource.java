package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.logging.Logger;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON)
public class LoginResource {
    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

    private final Gson g = new Gson();

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();



    public LoginResource() {}

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response doLogin(LoginData data) {
        LOG.fine("Attempt to login user: " + data.username);
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
        Entity user = datastore.get(userKey);

        if (user == null) {
            return Response.status(Status.FORBIDDEN).entity("user does not exist").build();
        }
        else if (!user.getString("password").equals(DigestUtils.sha512Hex(data.password))) {
            return Response.status(Status.FORBIDDEN).entity("wrong password").build();
        } else if (!user.getBoolean("state")) {
            return Response.status(Status.FORBIDDEN).entity("account not activated").build();
        } else {
            AuthToken at = new AuthToken(data.username);
            Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", data.username)).setKind("Token").newKey(at.tokenId);

            datastore.put(Entity.newBuilder((tokenKey))
                    .set("username", data.username)
                    .set("creationData", at.creationData)
                    .set("expirationData", at.expirationData).build());

            return Response.ok(g.toJson(at)).build();
        }
    }



}
