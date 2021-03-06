# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "time"
require "dalli"
require "yaml"

require_relative "util/location_constant"
require_relative "util/memcached_config"
require_relative "store/store_manager"

class LogStash::Filters::Intrusion < LogStash::Filters::Base
  include LocationConstant
  config_name "intrusion"

  config :memcached_server,   :validate => :string, :default => "",  :required => false
  config :update_stores_rate, :validate => :number,  :default => 60,                             :required => false

  public

  def register
    @dim_to_druid = [MARKET, MARKET_UUID, ORGANIZATION, ORGANIZATION_UUID,
                    DEPLOYMENT, DEPLOYMENT_UUID, SENSOR_NAME, SENSOR_UUID, 
                    NAMESPACE, SERVICE_PROVIDER, SERVICE_PROVIDER_UUID]
    @memcached_server = MemcachedConfig::servers if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0})
    @store_manager = StoreManager.new(@memcached, @update_stores_rate)
    @last_refresh_stores = nil
  end

  def filter(event)
    messageEnrichmentStore = @store_manager.enrich(event.to_hash)
    e = LogStash::Event.new
    messageEnrichmentStore.each { |k,v| e.set(k,v) }
    yield e

   event.cancel
  end  # def filter
end    # class Logstash::Filter::Intrusion

