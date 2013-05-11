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

#include "xauth_radius_plugin.h"
#include "xauth_radius.h"

#include <radius_client.h>
#include <radius_config.h>
#include <daemon.h>
#include <hydra.h>
#include <threading/rwlock.h>
#include <processing/jobs/callback_job.h>
#include <processing/jobs/delete_ike_sa_job.h>

/**
 * Default RADIUS server port for authentication
 */
#define AUTH_PORT 1812

/**
 * Default RADIUS server port for accounting
 */
#define ACCT_PORT 1813

typedef struct private_xauth_radius_plugin_t private_xauth_radius_plugin_t;

/**
 * Private data of an eap_radius_plugin_t object.
 */
struct private_xauth_radius_plugin_t {

	/**
	 * Public radius_plugin_t interface.
	 */
	xauth_radius_plugin_t public;

	/**
	 * List of RADIUS server configurations
	 */
	linked_list_t *configs;

	/**
	 * Lock for configs list
	 */
	rwlock_t *lock;

};


/**
 * Instance of the EAP plugin
 */
static private_xauth_radius_plugin_t *instance = NULL;

/**
 * Load RADIUS servers from configuration
 */
static void load_configs(private_xauth_radius_plugin_t *this)
{
	enumerator_t *enumerator;
	radius_config_t *config;
	char *nas_identifier, *secret, *address, *section;
	int auth_port, acct_port, sockets, preference;

	address = lib->settings->get_str(lib->settings,
					"%s.plugins.xauth-radius.server", NULL, charon->name);
	if (address)
	{	/* legacy configuration */
		secret = lib->settings->get_str(lib->settings,
					"%s.plugins.xauth-radius.secret", NULL, charon->name);
		if (!secret)
		{
			DBG1(DBG_CFG, "no RADIUS secret defined");
			return;
		}
		nas_identifier = lib->settings->get_str(lib->settings,
					"%s.plugins.xauth-radius.nas_identifier", "strongSwan",
					charon->name);
		auth_port = lib->settings->get_int(lib->settings,
					"%s.plugins.xauth-radius.port", AUTH_PORT, charon->name);
		sockets = lib->settings->get_int(lib->settings,
					"%s.plugins.xauth-radius.sockets", 1, charon->name);
		config = radius_config_create(address, address, auth_port, ACCT_PORT,
									  nas_identifier, secret, sockets, 0);
		if (!config)
		{
			DBG1(DBG_CFG, "no RADUIS server defined");
			return;
		}
		this->configs->insert_last(this->configs, config);
		return;
	}

	enumerator = lib->settings->create_section_enumerator(lib->settings,
								"%s.plugins.xauth-radius.servers", charon->name);
	while (enumerator->enumerate(enumerator, &section))
	{
		address = lib->settings->get_str(lib->settings,
							"%s.plugins.xauth-radius.servers.%s.address", NULL,
							charon->name, section);
		if (!address)
		{
			DBG1(DBG_CFG, "RADIUS server '%s' misses address, skipped", section);
			continue;
		}
		secret = lib->settings->get_str(lib->settings,
							"%s.plugins.xauth-radius.servers.%s.secret", NULL,
							charon->name, section);
		if (!secret)
		{
			DBG1(DBG_CFG, "RADIUS server '%s' misses secret, skipped", section);
			continue;
		}
		nas_identifier = lib->settings->get_str(lib->settings,
				"%s.plugins.xauth-radius.servers.%s.nas_identifier", "strongSwan",
				charon->name, section);
		auth_port = lib->settings->get_int(lib->settings,
			"%s.plugins.xauth-radius.servers.%s.auth_port",
				lib->settings->get_int(lib->settings,
					"%s.plugins.xauth-radius.servers.%s.port",
					AUTH_PORT, charon->name, section),
			charon->name, section);
		acct_port = lib->settings->get_int(lib->settings,
				"%s.plugins.xauth-radius.servers.%s.acct_port", ACCT_PORT,
				charon->name, section);
		sockets = lib->settings->get_int(lib->settings,
				"%s.plugins.xauth-radius.servers.%s.sockets", 1,
				charon->name, section);
		preference = lib->settings->get_int(lib->settings,
				"%s.plugins.xauth-radius.servers.%s.preference", 0,
				charon->name, section);
		config = radius_config_create(section, address, auth_port, acct_port,
								nas_identifier, secret, sockets, preference);
		if (!config)
		{
			DBG1(DBG_CFG, "loading RADIUS server '%s' failed, skipped", section);
			continue;
		}
		this->configs->insert_last(this->configs, config);
	}
	enumerator->destroy(enumerator);

	DBG1(DBG_CFG, "loaded %d RADIUS server configuration%s for xauth-radius",
		 this->configs->get_count(this->configs),
		 this->configs->get_count(this->configs) == 1 ? "" : "s");
}


METHOD(plugin_t, get_name, char*,
	private_xauth_radius_plugin_t *this)
{
	return "xauth-radius";
}

METHOD(plugin_t, get_features, int,
	private_xauth_radius_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(xauth_method_register, xauth_radius_create_server),
			PLUGIN_PROVIDE(XAUTH_SERVER, "radius"),
		PLUGIN_CALLBACK(xauth_method_register, xauth_radius_create_peer),
			PLUGIN_PROVIDE(XAUTH_PEER, "radius"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_xauth_radius_plugin_t *this)
{
	this->lock->destroy(this->lock);
	free(this);
	instance = NULL;
}

/*
 * see header file
 */
plugin_t *xauth_radius_plugin_create()
{
	private_xauth_radius_plugin_t *this;

	INIT(this,
                .public = {
		    .plugin = {
			    .get_name = _get_name,
			    .get_features = _get_features,
			    .destroy = _destroy,
		    },
                },
	    .configs = linked_list_create(),
	    .lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	load_configs(this);
        instance = this ;                    
	return &this->public.plugin;
}

/**
 * See header
 */
radius_client_t *xauth_radius_create_client()
{
	if (instance)
	{
		enumerator_t *enumerator;
		radius_config_t *config, *selected = NULL;
		int current, best = -1;

		instance->lock->read_lock(instance->lock);
		enumerator = instance->configs->create_enumerator(instance->configs);
		while (enumerator->enumerate(enumerator, &config))
		{
			current = config->get_preference(config);
			if (current > best ||
				/* for two with equal preference, 50-50 chance */
				(current == best && random() % 2 == 0))
			{
				DBG2(DBG_CFG, "RADIUS server '%s' is candidate: %d",
					 config->get_name(config), current);
				best = current;
				DESTROY_IF(selected);
				selected = config->get_ref(config);
			}
			else
			{
				DBG2(DBG_CFG, "RADIUS server '%s' skipped: %d",
					 config->get_name(config), current);
			}
		}
		enumerator->destroy(enumerator);
		instance->lock->unlock(instance->lock);

		if (selected)
		{
			return radius_client_create(selected);
		}
	}
	return NULL;
}

/**
 * Job to delete all active IKE_SAs
 */
static job_requeue_t delete_all_async(void *data)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;

	enumerator = charon->ike_sa_manager->create_enumerator(
												charon->ike_sa_manager, TRUE);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		lib->processor->queue_job(lib->processor,
				(job_t*)delete_ike_sa_job_create(ike_sa->get_id(ike_sa), TRUE));
	}
	enumerator->destroy(enumerator);

	return JOB_REQUEUE_NONE;
}

/**
 * See header.
 */
void xauth_radius_handle_timeout(ike_sa_id_t *id)
{
	charon->bus->alert(charon->bus, ALERT_RADIUS_NOT_RESPONDING);

	if (lib->settings->get_bool(lib->settings,
								"%s.plugins.xauth-radius.close_all_on_timeout",
								FALSE, charon->name))
	{
		DBG1(DBG_CFG, "deleting all IKE_SAs after RADIUS timeout");
		lib->processor->queue_job(lib->processor,
				(job_t*)callback_job_create_with_prio(
						(callback_job_cb_t)delete_all_async, NULL, NULL,
						(callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));
	}
	else if (id)
	{
		DBG1(DBG_CFG, "deleting IKE_SA after RADIUS timeout");
		lib->processor->queue_job(lib->processor,
				(job_t*)delete_ike_sa_job_create(id, TRUE));
	}
}


