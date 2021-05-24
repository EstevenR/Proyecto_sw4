using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;

        public AccountController(DataContext context)
         {
            _context = context;
         }

        
        [HttpPost("regiter")]
        public async Task<ActionResult<AppUser>> Register(RegisterDTO registerDTO)
         {
              if(await UserExist(registerDTO.UserName)) return BadRequest("UserName ya existe");
              
              using var hmac = new HMACSHA512();
         
              
              var user = new AppUser
              {
                 UserName = registerDTO.UserName.ToLower(),
                 PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
                 PasswordSalt = hmac.Key
              };
            
               _context.Users.Add(user);
               await _context.SaveChangesAsync();

               return user;
         }  [HttpPost("longin")]

           public async Task<ActionResult<AppUser>> Login(LoginDTO loginDTO)
           {
              var user =  await _context.Users.SingleOrDefaultAsync(user => user.UserName == loginDTO.UserName);

              if(user == null) return Unauthorized("Usuario invalido");

              using var  hmc = new HMACSHA512 (user.PasswordSalt);
              var ComputeHash = hmc.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.Password));

              for(int i = 0; i < ComputeHash.Length; i++)
              {
                 if(ComputeHash[i] != user.PasswordSalt[i]) return Unauthorized("Password invalido");
              }

              return user;
              
           }
         

         private async Task<bool>UserExist(string username)
         {
          return await _context.Users.AnyAsync(variable => variable.UserName == username.ToLower());
         }
     }
}
