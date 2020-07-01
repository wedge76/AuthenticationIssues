using System.Collections.Generic;
using IdentityModel;
using IdentityServer4.Models;

namespace myCompany.Person.Web
{
    public static class Config
    {
        private const string PersonApiResourceName = "Person.Api";

        private static readonly IdentityResource CustomProfile = new IdentityResource(name: "custom.profile",
                                                                              displayName: "Custom profile",
                                                                              claimTypes: new[]
                                                                                          {
                                                                                              "role",
                                                                                              "allowedAccess"
                                                                                          });

        public static IEnumerable<IdentityResource> Ids =>
            new[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Email(),
                new IdentityResources.Profile(),
                CustomProfile
            };

        public static IEnumerable<ApiResource> Apis =>
            new List<ApiResource>
            {
                new ApiResource(PersonApiResourceName,
                                "myCompany Person Api",
                                new[]
                                {
                                    "allowedAccess",
                                    "role"
                                }),
                new ApiResource("Translation.Api",
                                "myCompany Translation Api",
                                new[]
                                {
                                    JwtClaimTypes.Name,
                                    JwtClaimTypes.FamilyName,
                                    JwtClaimTypes.GivenName,
                                    JwtClaimTypes.Email,
                                    "allowedAccess",
                                }),
                new ApiResource("Integration.Api",
                                "myCompany Integration Api",
                                new[]
                                {
                                    JwtClaimTypes.Name,
                                    JwtClaimTypes.Email,
                                    "allowedAccess",
                                    "role"
                                }),
                new ApiResource("DataRegulation.Api",
                                "myCompany Data Regulation Api",
                                new[]
                                {
                                    JwtClaimTypes.Name,
                                    JwtClaimTypes.Email,
                                    "allowedAccess",
                                    "role"
                                })
            };
    }
}