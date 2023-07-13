using Microsoft.AspNetCore.Mvc;
using Sinqia4Devs.Utils.Cryptography;

namespace EncryptAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EncryptAESController : ControllerBase
    {
        [HttpPost]
        public IActionResult Encrypt([FromHeader(Name = "publicKey")] string publicKey, [FromBody] string parametroBody)
        {

            string XSINQIARequest = AesRsa.Encrypt(parametroBody, publicKey);

            return Ok(XSINQIARequest);
        }
    }
}
    