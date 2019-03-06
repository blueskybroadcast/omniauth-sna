require "omniauth-sna/version"
require "omniauth/strategies/sna"

module Omniauth
  module SNA
    OmniAuth.config.add_camelization 'sna', 'SNA'
  end
end
