/*
 * Copyright (C) 2011 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2013 Gerald Richter
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "xauth_radius.h"
#include "xauth_radius_plugin.h"

#include <radius_message.h>
#include <radius_client.h>
#include <daemon.h>
#include <library.h>

typedef struct private_xauth_radius_t private_xauth_radius_t;

/**
 * Private data of an xauth_radius_t object.
 */
struct private_xauth_radius_t {

	/**
	 * Public interface.
	 */
	xauth_radius_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * Challenge Response to sent
	 */
        chunk_t           message;  

       	/**
	 * RADIUS client instance
	 */
	radius_client_t *client;



};

METHOD(xauth_method_t, initiate_peer, status_t,
	private_xauth_radius_t *this, cp_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

METHOD(xauth_method_t, process_peer, status_t,
	private_xauth_radius_t *this, cp_payload_t *in, cp_payload_t **out)
{
	shared_key_t *shared;
	cp_payload_t *cp;
	chunk_t user, pass;

	shared = lib->credmgr->get_shared(lib->credmgr, SHARED_EAP, this->peer,
									  this->server);
	if (!shared)
	{
		DBG1(DBG_IKE, "no XAuth secret found for '%Y' - '%Y'", this->peer,
			 this->server);
		return FAILED;
	}

	user = this->peer->get_encoding(this->peer);
	pass = shared->get_key(shared);

	cp = cp_payload_create_type(CONFIGURATION_V1, CFG_REPLY);
	cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_NAME, user));
	cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_PASSWORD, pass));
	shared->destroy(shared);
	*out = cp;
	return NEED_MORE;
}

METHOD(xauth_method_t, initiate_server, status_t,
	private_xauth_radius_t *this, cp_payload_t **out)
{
	cp_payload_t *cp;

	cp = cp_payload_create_type(CONFIGURATION_V1, CFG_REQUEST);
	cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_NAME, chunk_empty));
	cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_PASSWORD, chunk_empty));

        if (this->message.ptr)
        {
	    DBG2(DBG_IKE, "XAUTH: add message %B", this->message);
	    cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_MESSAGE, this -> message));
            // chunk_free(&this->message) ;
            this->message = chunk_empty ;
        }

	*out = cp;
	return NEED_MORE;
}

METHOD(xauth_method_t, process_server, status_t,
	private_xauth_radius_t *this, cp_payload_t *in, cp_payload_t **out)
{
	configuration_attribute_t *attr;
	enumerator_t *enumerator;
	identification_t *id;
	chunk_t user = chunk_empty, pass = chunk_empty;
	status_t status = FAILED;
	radius_message_t *request, *response;
	cp_payload_t *cp;
	chunk_t reply_msg = chunk_empty;
	int type;
#ifdef XAUTH_RADIUS_FALLBACK
	int tried = 0;
	shared_key_t *shared;
#endif

	enumerator = in->create_attribute_enumerator(in);
	while (enumerator->enumerate(enumerator, &attr))
	{
		switch (attr->get_type(attr))
		{
			case XAUTH_USER_NAME:
				user = attr->get_chunk(attr);
				break;
			case XAUTH_USER_PASSWORD:
				pass = attr->get_chunk(attr);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (!user.ptr || !pass.ptr)
	{
		DBG1(DBG_IKE, "peer did not respond to our XAuth request");
		return FAILED;
	}
	if (user.len)
	{
		id = identification_create_from_data(user);
		if (!id)
		{
			DBG1(DBG_IKE, "failed to parse provided XAuth username");
			return FAILED;
		}
		this->peer->destroy(this->peer);
		this->peer = id;
	}
	if (pass.len && pass.ptr[pass.len - 1] == 0)
	{	/* fix null-terminated passwords (Android etc.) */
		pass.len -= 1;
	}

	request = radius_message_create(RMC_ACCESS_REQUEST);

	request->add(request, RAT_USER_NAME, user);
	request->add(request, RAT_USER_PASSWORD, pass);

	DBG2(DBG_IKE, "XAUTH: send access request to radiusserver for user %B", &user);
	response = this->client->request(this->client, request);
	if (response)
	{
	    switch (response->get_code(response))
            {
                case RMC_ACCESS_ACCEPT:
                    DBG1(DBG_IKE, "XAUTH: RADIUS authentication of '%Y' successful",  
					 this->peer) ;
                    status = SUCCESS;
		    break;
                case RMC_ACCESS_CHALLENGE:
	            enumerator = response->create_enumerator(response);
	            while (enumerator->enumerate(enumerator, &type, &reply_msg))
	            {
		            if (type == RAT_REPLY_MESSAGE && reply_msg.len)
		            {
                                    break ;
		            }
	            }
	            enumerator->destroy(enumerator);
	            if (reply_msg.len)
                    {
	                DBG2(DBG_IKE, "XAUTH: radius sent access challenge, reply-message %B", &reply_msg);

	                cp = cp_payload_create_type(CONFIGURATION_V1, CFG_REQUEST);
	                cp->add_attribute(cp, configuration_attribute_create_chunk(
				                CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_NAME, chunk_empty));
	                cp->add_attribute(cp, configuration_attribute_create_chunk(
				                CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_PASSWORD, chunk_empty));
	                cp->add_attribute(cp, configuration_attribute_create_chunk(
				            CONFIGURATION_ATTRIBUTE_V1, XAUTH_MESSAGE, reply_msg));

	                *out = cp;
	                status = NEED_MORE;
                    }
                    else
                        {
		        DBG1(DBG_IKE, "XAUTH: radius did not provide REPLY-MESSAGE attribute") ;
                        }
		    break;
		case RMC_ACCESS_REJECT:
		default:
		    DBG1(DBG_IKE, "XAUTH: radius rejected access for user %B", &user) ;
                    break ;
            }
        }
        else
	{
		xauth_radius_handle_timeout(NULL);
	}
	request->destroy(request);


#ifdef XAUTH_RADIUS_FALLBACK
        if (status != SUCCESS)
        {
            enumerator = lib->credmgr->create_shared_enumerator(lib->credmgr,
										    SHARED_EAP, this->server, this->peer);
	    while (enumerator->enumerate(enumerator, &shared, NULL, NULL))
	    {
		    if (chunk_equals(shared->get_key(shared), pass))
		    {
			    status = SUCCESS;
			    break;
		    }
		    tried++;
	    }
	    enumerator->destroy(enumerator);
	    if (status != SUCCESS)
	    {
		    if (!tried)
		    {
			    DBG1(DBG_IKE, "no XAuth secret found for '%Y' - '%Y'",
				     this->server, this->peer);
		    }
		    else
		    {
			    DBG1(DBG_IKE, "none of %d found XAuth secrets for '%Y' - '%Y' "
				     "matched", tried, this->server, this->peer);
		    }
	    }
        }
#endif
        return status;
}

METHOD(xauth_method_t, get_identity, identification_t*,
	private_xauth_radius_t *this)
{
	return this->peer;
}

METHOD(xauth_method_t, destroy, void,
	private_xauth_radius_t *this)
{
	this->server->destroy(this->server);
	this->peer->destroy(this->peer);
	this->client->destroy(this->client);
	free(this);
}

/*
 * Described in header.
 */
xauth_radius_t *xauth_radius_create_peer(identification_t *server,
										   identification_t *peer)
{
	private_xauth_radius_t *this;

	INIT(this,
		.public =  {
			.xauth_method = {
				.initiate = _initiate_peer,
				.process = _process_peer,
				.get_identity = _get_identity,
				.destroy = _destroy,
			},
		},
		.server = server->clone(server),
		.peer = peer->clone(peer),
	);

	return &this->public;
}

/*
 * Described in header.
 */
xauth_radius_t *xauth_radius_create_server(identification_t *server,
											 identification_t *peer)
{
	private_xauth_radius_t *this;

	INIT(this,
		.public = {
			.xauth_method = {
				.initiate = _initiate_server,
				.process = _process_server,
				.get_identity = _get_identity,
				.destroy = _destroy,
			},
		},
		.server = server->clone(server),
		.peer = peer->clone(peer),
	);
	this->client = xauth_radius_create_client();
	if (!this->client)
	{
		free(this);
		return NULL;
	}

	return &this->public;
}
