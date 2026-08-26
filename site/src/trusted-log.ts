import { b64uDecode } from './b64u.js'
import type { LogKey, AnchorPolicy } from 'attest-verifier'

// The verifier's own TRUSTED configuration — not evidence. Everything here is
// pinned out of band and shipped inside the page: v0.2 §7.3 forbids a verifier
// from taking log keys from the material it is checking, which is why these
// bytes are compiled in rather than fetched, and why the log does not serve a
// copy of them next to itself.
//
// Compiled in, also, so the page keeps the promise it makes to the reader: cut
// the network after it loads and verification still works. A JSON asset would
// have made this one more request.
//
// These are PUBLIC keys. The private halves that sign the checkpoints live
// outside this repository and are seen only by the signing ceremony.

export const LOG_ORIGIN = "attest-receipts.org/log"

export const LOG_KEYS: LogKey[] = [
  {
    origin: "attest-receipts.org/log",
    name: "attest-receipts.org/log",
    ed25519Pub: b64uDecode(
      "BrcLE0ExM6ucUjKeMzV68vYn8_T259N1pLzl6BUtTnM",
    ),
    mldsaPub: b64uDecode(
      "0pWKg1MIV_SFo2EQG-Uzd6EK_oQN8bPIT1D3H0aC8j_ELCK8hyUMDKs0gWHlZ00Ej3s08KhtxuL_JOmw74ZAyoL71ikzha6k4At9Ay5_5Em2HLZzw7h6lCNY5sLAoGjffLMptJHDHlp-oQ821Yzkwrd5cdxg_m4jF2hvs2CZZFUxA12gLHHRdjRj8nZKpxjRcJuENZ7ypXFjnKDWUXl2bt_x71rtL-s_GTslZmhS5rR8No031kALYPugioXlBIxh0rgl_uid5ecIlTTirBxTs6x3nKx7LKP6RJSldxdF0lCKcZVgzi9t3uhENKslIZcmPZQjj9n7s5-tb23zoRaTTd2NX8tdrq924oiovj4A2D01JuYfXR67WSVBRFDSJoCPAh-jT6fxN30oJgdH17IUW7GYg6FhkOvvA_cEkwVeW0Vr6masZTWodYFBRhbp7iA5HMxCACVqNDUSk2GbkH0OYFnXshgtfddCt5M3wazQvHfaz2Q9Ps9POoh2qD1TzxHj93IJgoRJBam8M71AWY3YDviS-jqeyXuI-LFb2eUGJT_8krATpjjY3RtEFz22mrxAlu-azTFEQvrk6d84-oAYTI-0INF9LUoK24eA6JPE1uAhroZEak54adAGDj-tnNh7OuRwp1Yze5HsDhTKCmX5wXknkaMhrciYxWmWqba2IgvbV3xPKTcM5xcDaPJ0m7fOuO0ryRkqyAOSpi_zwhTrhbXSPoaud0kMp40GKHUhUxNSz3Rj6uRVQFqKQSy97f3AvmBKID0bmvE30IzVKZapuEsQfKJxtVYj0JFlAIqTARN6hL9_De8IF21Nf7F6gAT0J86aQYRlN1aTFQGXFHUVPJ0nnnKCmQne_BDAzebL4QWaAzWBeFBDgt5dkqomqVnRH9nUtl8I5mESIdQ1kfmnTWMIvz9SpVRa-HVzI5Ixcp71BxFYlf5Du0KeHLees0qCjUs5Io7OzTePr9ZyOF3DjDFF5SEFUAV3ljaW_d8OCdmo4-aHbgL8cUg1jALjNxIK4iBTvyGBLCAza60th_GqZefTC18PqOpbPMCzL5Z7kP1oVJJ9E2rBoBfIGxs-HgCt6ilqG29L--HunBsPcNM66WDCDTIr0xCI7CmxxqjJkSKgaXNaq4ZBXYmMBVJr7YlX7lRn7ApCYR3HNniStp0UwOXFKUaG9N9mKskN1rfk-13uSs9Bf2eKtLkuM8cmB9m74l9Epw81L1uJ08Izc3WJzAyhn8jbj7Wqv5R4soSE5-u_OVfRF3gGMd1_ecYrjybmcb6X4HYTtJqgPUYn6JQOTVDo_QaRNwQ3ERkB6kS-EHjyiLkifOehBJ-gKVqxmn4Ygzv8QMtrHMalJ75dpJCMbSbT5MTWgZjWsHjiwyRW_COloC24ok7cmqK8bD16FRsJxkbCYGOUW8aMdykHakSvPlrXk4L-b0kBrHDzSH1s3QS6J8l2z_Iuf5JJDbbphIioc3i7boAN4U3C7ISiF4prrULSyju4CfEn3jzzS3ffWmtV43FrqYruCnSLaOgNWm5K23Hia4NhcE6ZfBqT7nJJboJg6GrWw77l0rYhooYsZOlFHV5f_ZEI7je6pOx7xRx-UTNsPLaQ7GkhxS049XtX_HbpZVmRA_XOwWsi07L3pTGY4TMO_mYKywF9Wwt57bq86Gn440pToi5rZreBjTAVWojuWwqOjEbJVrmAUPmAUnYw3eTGkwwsmDRYF_dv6lqfYqkVj8gvJzxnkz3IOeCeQYrfVtiuqYzMpiLG_dx2VKLIME8-BM8fdtpvZdOTj_twNc2yCgNXlqLsvgIp3iRtGfSV37mJGAlbfDyvMpq2GSXMMbTAuuELirDNHZVfvuVQSIGWRKlIuaKX5otT5jQa4H0fzeChDAZDbOPXnbQQ2Y6oKZDWgxDoY3vp76hEylkInY1-HI__TqfTOWvl-BqUfNtdojFjwo2uuQYb6ejdrGY-qzetKrXzmf4wEESp8B5e386THmAl1Jl8rtrG7QCy_qyU6e74tg8txKlrxhQImpRBWsZcO2fZEZEvvWgY775S6q_2_PFJb4mxYapxGz2Kx0dqD_OjVUtFUgooEdRWZ_OWwCeqcItVOLO_Z1AEZ1UeOIuaJXt7Z4TNoPs9_FsZ9vvqmHvp57adCvgwZdTwTr5XQXcYL2YvrdCjpx9j8hK0wzSLwjjNitmeHuaORqU4qTg869RSjjf97u41nW93VWKAUYn9zP7FsZbrh83M6qaJBsW4mvzixpZzBSQNN-Lfdfm8MkUE1trSOq9SxP3qVpY-jpG1SrGdT0PmTga7GYsjDnwAiYoVcAg9w3YHC3UDrAZ22G0vvQzZ6XMH_M9H4sWua0kJSM8g96H0whGg4snbVx08E-1lD7HkWCH2J6NZHQ2_-7iL-DcmHGCCclDQxd4xMQak5cO6IzrUGcu_uFjcjDyFAnd7y_xVJqBbZO2eqXLHlxEwPbKUUb4h2dZ2Dwa7dX1zjPTPT9vfUt4rdcJ6Z2hjOdVyV1pybzyk2Ro6T9y8FruxxbjKnnla23UoPIRkS0JU8_gTjmJsmcsUavN1LDsrbkfUXioYKekddFR16OuSPTfhsbgkyfLU3iVwd9s",
    ),
  },
]

// No anchor has been attached to a checkpoint yet, so nothing is pinned. This
// is NOT a placeholder that weakens anything: an empty policy simply pins no
// Bitcoin header, and a proof pointing at an unpinned header degrades to a
// warning while the receipt keeps its `logged` standing. Supplying the policy
// at all is half of the capability gate — without it, evidence is not even
// looked at. Entries appear here, one per block, once anchoring lands.
export const ANCHOR_POLICY: AnchorPolicy = { pinnedHeaders: {}, crqcHorizon: null }
