package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;
import org.apache.commons.codec.digest.DigestUtils;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.RegisterData;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.logging.Logger;
@Path("/register")
@Produces(MediaType.APPLICATION_JSON)
public class RegisterResource {

    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());

    private final Gson g = new Gson();

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response doRegistry(RegisterData data) {
        LOG.fine("Attempt to register user: " + data.username);
        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
        Entity person = datastore.get(userKey);

        if (!data.isPasswordValid()) {
            return Response.status(Status.FORBIDDEN).entity("input invalid").build();
        }
        else if (person != null) {
            return Response.status(Status.FORBIDDEN).entity("username already in use").build();
        }
        else {
            AuthToken at = new AuthToken(data.username);
            datastore.put(Entity.newBuilder(userKey)
                    .set("email", data.email)
                    .set("password", DigestUtils.sha512Hex(data.password))
                    .set("name", data.name)
                    .set("phone_number", data.phoneNumber)
                    .set("role", "USER")
                    .set("state", false)
                    .build());
            return Response.ok(g.toJson(at)).build();
        }
    }




}
