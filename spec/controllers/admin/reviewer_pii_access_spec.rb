require 'rails_helper'

# Security regression tests for finding F1: the reviewer role (the least
# privileged back-office role, AdminUser::REVIEWER_ROLE) must not be able to
# search for or export citizens' PII (signatory name, email, postcode, IP
# address, creator emails, internal moderation notes).
#
# The codebase shows these data are intended for moderator/sysadmin roles only:
# AdminUser#can_moderate_petitions? explicitly excludes reviewers, the admin
# views hide moderation actions from reviewers, and sibling controllers that
# touch the same data are guarded by require_moderator/require_sysadmin.
#
# The "is denied" examples below assert the ACCESS CONTROL THAT SHOULD EXIST.
# They currently FAIL because Admin::SignaturesController#index and
# Admin::PetitionsController#index only require a logged-in admin user
# (Authentication#require_admin checks current_user presence, not the role).
# A fix (e.g. before_action :require_moderator) will make them pass.
RSpec.describe Admin::SignaturesController, type: :controller, admin: true do
  render_views

  context "logged in as a reviewer user" do
    let(:user) { FactoryBot.create(:reviewer_user) }

    let!(:petition) { FactoryBot.create(:open_petition) }

    let!(:signature) do
      FactoryBot.create(:validated_signature,
        petition: petition,
        name: "Alice Jones",
        email: "alice@example.com",
        postcode: "SW1A 1AA",
        ip_address: "203.0.113.7"
      )
    end

    before { login_as(user) }

    describe "GET /admin/signatures?q=<email>" do
      it "is denied to reviewers" do
        get :index, params: { q: "alice@example.com" }

        expect(response).to redirect_to("https://moderate.petition.parliament.uk/admin")
        expect(controller).to set_flash[:alert].to("You must be logged in as a moderator or system administrator to view this page")
      end

      it "does not disclose the signatory's email address" do
        get :index, params: { q: "alice@example.com" }

        expect(response.body).not_to include("alice")
        expect(response.body).not_to include("@example.com")
      end
    end

    describe "GET /admin/signatures?q=<postcode>" do
      it "does not disclose the signatory's postcode" do
        get :index, params: { q: "SW1A 1AA" }

        expect(response.body).not_to include("SW1A 1AA")
      end
    end

    describe "GET /admin/signatures?q=<ip address>" do
      it "does not disclose the signatory's IP address" do
        get :index, params: { q: "203.0.113.7" }

        expect(response.body).not_to include("203.0.113.7")
      end
    end

    describe "GET /admin/signatures?q=<name>" do
      it "does not disclose the signatory's name" do
        get :index, params: { q: "Alice Jones" }

        expect(response.body).not_to include("Alice Jones")
      end
    end
  end
end

RSpec.describe Admin::PetitionsController, type: :controller, admin: true do
  context "logged in as a reviewer user" do
    let(:user) { FactoryBot.create(:reviewer_user) }

    let!(:petition) do
      FactoryBot.create(:open_petition,
        creator_email: "bob.the.creator@example.com",
        admin_notes: "INTERNAL NOTE: possible fraud pattern, do not disclose"
      )
    end

    before { login_as(user) }

    describe "GET /admin/petitions.csv" do
      # The CSV response body is streamed as an Enumerator, so materialize it
      # before asserting on its contents.
      def csv_body
        response.body.to_a.join
      end

      it "is denied to reviewers" do
        get :index, format: :csv

        expect(response.status).to eq(302)
        expect(response).to redirect_to("https://moderate.petition.parliament.uk/admin")
        expect(controller).to set_flash[:alert].to("You must be logged in as a moderator or system administrator to view this page")
      end

      it "does not export the petition creator's email address" do
        get :index, format: :csv

        expect(csv_body).not_to include("bob.the.creator@example.com")
      end

      it "does not export internal moderation notes" do
        get :index, format: :csv

        expect(csv_body).not_to include("INTERNAL NOTE: possible fraud pattern")
      end
    end
  end
end

# Negative control: this proves the reviewer role IS recognized and IS blocked
# by correctly guarded sibling controllers that manipulate the same petitions.
# This example passes today, demonstrating that the missing authorization on
# Admin::SignaturesController and Admin::PetitionsController is an
# inconsistency, not an intentional design decision.
RSpec.describe Admin::PetitionEmailsController, type: :controller, admin: true do
  context "logged in as a reviewer user" do
    let(:user) { FactoryBot.create(:reviewer_user) }
    let!(:petition) { FactoryBot.create(:open_petition) }

    before { login_as(user) }

    describe "GET /admin/petitions/:petition_id/petition_emails/new" do
      it "is denied to reviewers" do
        get :new, params: { petition_id: petition.id }

        expect(response).to redirect_to("https://moderate.petition.parliament.uk/admin")
        expect(controller).to set_flash[:alert].to("You must be logged in as a moderator or system administrator to view this page")
      end
    end
  end
end
