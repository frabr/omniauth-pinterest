require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Pinterest < OmniAuth::Strategies::OAuth2
      option :client_options, {
        site: 'https://api.pinterest.com/',
        authorize_url: 'https://www.pinterest.com/oauth/',
        token_url: 'https://api.pinterest.com/v5/oauth/token'
      }

      def request_phase
        options[:scope] ||= 'pins:read'
        options[:response_type] ||= 'code'
        super
      end

      def callback_url
        options[:callback_url] || full_host + script_name + callback_path
      end

      uid { raw_info['username'] }

      
      info { raw_info }


      def callback_phase
        options[:token_params][:headers] = {
          Authorization: "Basic #{Base64.strict_encode64("#{options[:client_id]}:#{options[:client_secret]}")}"
        }
        super
      end

      credentials do
        puts access_token.params
        hash = { 'token' => access_token.token }
        hash['refresh_token'] = access_token.refresh_token if access_token.expires? && access_token.refresh_token
        hash['expires_at'] = access_token.expires_at if access_token.expires?
        hash['expires'] = access_token.expires?
        hash['refresh_token_expires_at'] = (DateTime.now + access_token.params["refresh_token_expires_in"].to_i.seconds).to_i
        hash['scope'] = access_token.params["scope"]

        hash
      end

      def authorize_params
        super.tap do |params|
          %w[redirect_uri].each do |v|
            params[:redirect_uri] = request.params[v] if request.params[v]
          end
        end
      end

      def raw_info
        puts access_token.inspect
        @raw_info ||= access_token.get('/v5/user_account').parsed
      end

      def ssl?
        true
      end
    end
  end
end
