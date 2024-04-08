package pt.unl.fct.di.apdc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.logging.Logger;


@Path("/root")
public class StartUpResource {

	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	public StartUpResource() {
	}

	@POST
	@Path("/")
	public Response initialize() {
		LOG.fine("Attempt to create root user");
		Key userKey = datastore.newKeyFactory().setKind("User").newKey("root");
		Entity user = datastore.get(userKey);
		if(user==null) datastore.put(Entity.newBuilder(userKey).set("name", "root").set("email", "root@root.com").set("phone_number", "000000000").set("role", "SU").set("state", true).set("password", DigestUtils.sha512Hex("root")).build());
		return Response.ok().build();
	}


}
