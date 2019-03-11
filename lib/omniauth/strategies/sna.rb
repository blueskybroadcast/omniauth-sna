require 'omniauth-oauth2'
require 'rest_client'
require 'multi_xml'

module OmniAuth
  module Strategies
    class SNA < OmniAuth::Strategies::OAuth2
      option :name, 'sna'
      option :app_options, { app_event_id: nil }
      option :client_options, {
        login_page_url: 'MUST BE SET',
        api_endpoint: 'MUST BE SET',
        token: 'MUST BE SET',
        sync_custom_fields: false,
        custom_field_keys: []
      }

      uid { raw_user_info[:id] }
      info { raw_user_info }

      def request_phase
        redirect login_page_url_with_redirect
      end

      def callback_phase
        slug = account_slug
        account = Account.find_by(slug: slug)
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + slug
        self.env['omniauth.app_event_id'] = @app_event.id
        call_app!
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash.extra = extra
        hash
      end

      def raw_user_info
        @raw_user_info ||= get_user_info
      end

      def get_user_info
        request_params = { id: request.params['id'], ln: request.params['ln'], token: options.client_options.token }
        request_log_text = "#{provider_name} Get Member Info Request:\nGET #{user_info_url}, params: #{request_params.merge(token: Provider::SECURITY_MASK)}"
        @app_event.logs.create(level: 'info', text: request_log_text)

        begin
          response = RestClient.get(user_info_url, params: request_params)
        rescue RestClient::ExceptionWithResponse => e
          error_log_text = "#{provider_name} Get Member Info Response Error #{e.message} (code: #{e.response&.code}):\n#{e.response}"
          @app_event.logs.create(level: 'error', text: error_log_text)
          @app_event.fail!
          return {}
        end

        response_log_text = "#{provider_name} Get Member Info Response (code: #{response.code}): \n#{response.body}"
        @app_event.logs.create(level: 'info', text: response_log_text)
        parsed_response = MultiXml.parse(response)['string']
        parsed_user_node = MultiXml.parse(parsed_response).dig('NewDataSet', 'Webuser')

        unless parsed_user_node
          error_log_text = "#{provider_name} Get Member Info: User not found!"
          @app_event.logs.create(level: 'error', text: error_log_text)
          @app_event.fail!
          return {}
        end

        info = {
          id: parsed_user_node['ID'],
          first_name: parsed_user_node['FirstName'],
          last_name: parsed_user_node['LastName'],
          email: parsed_user_node['Email1'],
          member_type: parsed_user_node['MemberType']
        }
        info[:custom_fields_data] = custom_fields_data(parsed_user_node) if options.client_options.sync_custom_fields

        @app_event.update(raw_data: {
          user_info: {
            uid: info[:id],
            email: info[:email],
            first_name: info[:first_name],
            last_name: info[:last_name]
          }
        })

        info
      end

      private

      def custom_fields_data(parsed_user_node)
        options.client_options.custom_field_keys.each_with_object({}) do |key, hash|
          hash[key.downcase] = parsed_user_node[key]
        end
      end

      def login_page_url_with_redirect
        "#{options.client_options.login_page_url}?returnUrl=#{return_url_key}"
      end

      def return_url_key
        current_url = URI.parse(full_host)
        return 'Local' if current_url.scheme == 'http'
        return 'Dev' if current_url.host =~ /dev.pathlms/
        return 'Staging' if current_url.host =~ /staging.pathlms/
        'Production'
      end

      def user_info_url
        "#{options.client_options.api_endpoint}/GetMemberType"
      end

      def provider_name
        options.name
      end

      def account_slug
        request.params['slug'].presence ||
          self.env['omniauth.origin']&.gsub(/\//, '') ||
          session['omniauth.origin']&.gsub(/\//, '')
      end
    end
  end
end
